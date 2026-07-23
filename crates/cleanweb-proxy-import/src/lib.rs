use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_yaml::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyImportReport {
    pub detected_format: String,
    pub proxy_count: usize,
    pub group_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyImport {
    pub report: ProxyImportReport,
    pub payload: String,
}

pub fn parse_proxy_payload(text: &str) -> Result<ProxyImport, String> {
    // 尝试直接解析为 Clash YAML
    if let Some(result) = try_parse_clash_yaml(text)? {
        return Ok(result);
    }
    // 尝试 base64 解码（很多订阅商会把整个 Clash 配置 base64 后返回）
    if let Some(decoded) =
        flexible_base64_decode(text.trim()).and_then(|s| String::from_utf8(s).ok())
    {
        if let Some(result) = try_parse_clash_yaml(&decoded)? {
            return Ok(result);
        }
    }
    // 作为 URI 列表处理
    let decoded_text = flexible_base64_decode(text.trim())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| text.to_owned());
    let supported = [
        "ss://",
        "ssr://",
        "vmess://",
        "vless://",
        "trojan://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "socks://",
        "http://",
        "https://",
        "wireguard://",
    ];
    let count = decoded_text
        .lines()
        .filter(|line| {
            supported
                .iter()
                .any(|prefix| line.trim().starts_with(prefix))
        })
        .count();
    if count == 0 {
        return Err("未找到支持的代理节点或代理组".into());
    }
    // 将 URI 列表转换为 Clash YAML 格式
    let proxies = uri_list_to_clash_proxies(&decoded_text);
    if proxies.is_empty() {
        return Err("无法解析任何代理节点".into());
    }
    let mut clean = serde_yaml::Mapping::new();
    clean.insert(Value::String("proxies".into()), Value::Sequence(proxies));
    let payload = serde_yaml::to_string(&clean).map_err(error)?;
    Ok(ProxyImport {
        report: ProxyImportReport {
            detected_format: "clash".into(),
            proxy_count: count,
            group_count: 0,
        },
        payload,
    })
}

/// 将 URI 列表（ss://, vmess://, vless://, trojan:// 等）转换为 Clash YAML proxy 条目
fn uri_list_to_clash_proxies(text: &str) -> Vec<Value> {
    let mut result = Vec::new();
    let mut index = 1;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(proxy) = parse_single_uri(line, &mut index) {
            result.push(proxy);
        }
    }
    result
}

#[doc(hidden)]
pub fn parse_single_uri(uri: &str, index: &mut usize) -> Option<Value> {
    // 分离 fragment (节点名称)
    // 只在 '@' 之后查找 '#'，避免 base64 密码中的 '#' 被错误识别为 fragment 分隔符
    let (main, name) = {
        let at_pos = uri.find('@');
        let search_start = at_pos.map(|p| p + 1).unwrap_or(0);
        match uri[search_start..].rfind('#') {
            Some(rel_pos) => {
                let abs_pos = search_start + rel_pos;
                (
                    &uri[..abs_pos],
                    url_decode(&uri[abs_pos + 1..].replace('+', " ")),
                )
            }
            None => (uri, format!("节点{}", index)),
        }
    };
    *index += 1;

    if let Some(rest) = main.strip_prefix("ss://") {
        return parse_ss(rest, &name);
    }
    if let Some(rest) = main.strip_prefix("ssr://") {
        return parse_ssr(rest, &name);
    }
    if let Some(rest) = main.strip_prefix("vmess://") {
        return parse_vmess(rest, &name);
    }
    if let Some(rest) = main.strip_prefix("vless://") {
        return parse_vless_trojan(rest, &name, "vless");
    }
    if let Some(rest) = main.strip_prefix("trojan://") {
        return parse_vless_trojan(rest, &name, "trojan");
    }
    if let Some(rest) = main.strip_prefix("hysteria2://") {
        return parse_vless_trojan(rest, &name, "hysteria2");
    }
    if let Some(rest) = main.strip_prefix("hy2://") {
        return parse_vless_trojan(rest, &name, "hysteria2");
    }
    if let Some(rest) = main.strip_prefix("hysteria://") {
        return parse_hysteria(rest, &name);
    }
    if let Some(rest) = main.strip_prefix("tuic://") {
        return parse_tuic(rest, &name);
    }
    if let Some(rest) = main
        .strip_prefix("socks5://")
        .or_else(|| main.strip_prefix("socks://"))
    {
        return parse_socks(rest, &name);
    }
    if let Some(rest) = main
        .strip_prefix("http://")
        .or_else(|| main.strip_prefix("https://"))
    {
        return parse_http_proxy(rest, &name);
    }
    None
}

fn parse_ss(rest: &str, name: &str) -> Option<Value> {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "ss".into());

    // Strip query parameters (e.g. ?group=xxx) and trailing path '/' before parsing authority
    let rest = match rest.split_once('?') {
        Some((r, _)) => r,
        None => rest,
    };
    let rest = rest.trim_end_matches('/');

    // SIP002 format: method_b64:password_b64@host:port
    if let Some((userinfo, hostport)) = rest.split_once('@') {
        if let Some((method_b64, password_b64)) = userinfo.split_once(':') {
            // Each part is individually base64-encoded
            let method = flexible_base64_decode(method_b64)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| method_b64.to_string());
            let password = flexible_base64_decode(password_b64)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| password_b64.to_string());
            map.insert("cipher".into(), method.into());
            map.insert("password".into(), password.into());
        } else {
            // Entire userinfo is base64-encoded "method:password"
            let decoded = flexible_base64_decode(userinfo)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| userinfo.to_string());
            if let Some((method, password)) = decoded.split_once(':') {
                map.insert("cipher".into(), method.into());
                map.insert("password".into(), password.into());
            }
        }
        if let Some((host, port)) = hostport.rsplit_once(':') {
            map.insert("server".into(), host.into());
            map.insert("port".into(), port.parse::<u32>().ok()?.into());
        }
    } else {
        // 旧格式: base64(method:password@host:port)
        let decoded = flexible_base64_decode(rest).and_then(|b| String::from_utf8(b).ok())?;
        if let Some((method_pass, hostport)) = decoded.rsplit_once('@') {
            if let Some((method, password)) = method_pass.split_once(':') {
                map.insert("cipher".into(), method.into());
                map.insert("password".into(), password.into());
            }
            if let Some((host, port)) = hostport.rsplit_once(':') {
                map.insert("server".into(), host.into());
                map.insert("port".into(), port.parse::<u32>().ok()?.into());
            }
        }
    }
    map.get("server")?;
    Some(Value::Mapping(map))
}

fn parse_vmess(rest: &str, name: &str) -> Option<Value> {
    let decoded = flexible_base64_decode(rest).and_then(|b| String::from_utf8(b).ok())?;
    let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;
    let get = |k: &str| json.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "vmess".into());
    map.insert("server".into(), get("add").into());
    map.insert("port".into(), get("port").parse::<u32>().ok()?.into());
    map.insert("uuid".into(), get("id").into());
    map.insert(
        "alterId".into(),
        get("aid").parse::<u32>().unwrap_or(0).into(),
    );
    let scy = get("scy");
    map.insert(
        "cipher".into(),
        (if scy.is_empty() { "auto" } else { scy }).into(),
    );
    let network = get("net");
    if !network.is_empty() {
        map.insert("network".into(), network.into());
    }
    if (network == "ws" || network == "h2" || network == "grpc") && !get("path").is_empty() {
        map.insert(
            format!("{}-opts", network).as_str().into(),
            {
                let mut opts = serde_yaml::Mapping::new();
                opts.insert("path".into(), get("path").into());
                if !get("host").is_empty() {
                    opts.insert(
                        "headers".into(),
                        {
                            let mut h = serde_yaml::Mapping::new();
                            h.insert("Host".into(), get("host").into());
                            h
                        }
                        .into(),
                    );
                }
                opts
            }
            .into(),
        );
    }
    let tls = get("tls");
    if tls == "tls" {
        map.insert("tls".into(), true.into());
        if !get("sni").is_empty() {
            map.insert("servername".into(), get("sni").into());
        }
    }
    Some(Value::Mapping(map))
}

fn parse_vless_trojan(rest: &str, name: &str, ptype: &str) -> Option<Value> {
    // 格式: password(or uuid)@host:port?params
    let (auth, hostport_query) = rest.split_once('@')?;
    let (hostport, query) = match hostport_query.split_once('?') {
        Some((h, q)) => (h, q),
        None => (hostport_query, ""),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let params: std::collections::HashMap<&str, &str> =
        query.split('&').filter_map(|p| p.split_once('=')).collect();

    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), ptype.into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.parse::<u32>().ok()?.into());

    if ptype == "vless" {
        map.insert("uuid".into(), url_decode(auth).into());
        map.insert("udp".into(), true.into());
    } else if ptype == "trojan" {
        map.insert("password".into(), url_decode(auth).into());
        map.insert("udp".into(), true.into());
    } else if ptype == "hysteria2" {
        map.insert("password".into(), url_decode(auth).into());
    }

    let network = params.get("type").copied().unwrap_or("tcp");
    if network != "tcp" {
        map.insert("network".into(), network.into());
    }
    if network == "ws" || network == "grpc" || network == "h2" {
        let mut opts = serde_yaml::Mapping::new();
        if let Some(path) = params.get("path") {
            opts.insert("path".into(), url_decode(path).into());
        }
        if let Some(host) = params.get("host") {
            if network == "ws" {
                opts.insert(
                    "headers".into(),
                    {
                        let mut h = serde_yaml::Mapping::new();
                        h.insert("Host".into(), url_decode(host).into());
                        h
                    }
                    .into(),
                );
            } else {
                opts.insert("host".into(), url_decode(host).into());
            }
        }
        if let Some(sni) = params.get("sni") {
            opts.insert("servername".into(), url_decode(sni).into());
        }
        map.insert(format!("{}-opts", network).as_str().into(), opts.into());
    }
    let security = params.get("security").copied().unwrap_or("");
    if security == "tls" || ptype == "trojan" || ptype == "hysteria2" {
        map.insert("tls".into(), true.into());
        if let Some(sni) = params.get("sni") {
            map.insert("servername".into(), url_decode(sni).into());
        }
        if params
            .get("allowInsecure")
            .map(|v| *v == "1")
            .unwrap_or(false)
        {
            map.insert("skip-cert-verify".into(), true.into());
        }
    }
    if ptype == "hysteria2" {
        if let Some(obfs) = params.get("obfs") {
            map.insert("obfs".into(), "salamander".into());
            map.insert("obfs-password".into(), url_decode(obfs).into());
        }
    }
    Some(Value::Mapping(map))
}

fn parse_tuic(rest: &str, name: &str) -> Option<Value> {
    let (auth, hostport_query) = rest.split_once('@')?;
    let (hostport, query) = match hostport_query.split_once('?') {
        Some((h, q)) => (h, q),
        None => (hostport_query, ""),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let params: std::collections::HashMap<&str, &str> =
        query.split('&').filter_map(|p| p.split_once('=')).collect();
    let (uuid, password) = auth.split_once(':')?;

    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "tuic".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.parse::<u32>().ok()?.into());
    map.insert("uuid".into(), url_decode(uuid).into());
    map.insert("password".into(), url_decode(password).into());
    map.insert("udp".into(), true.into());
    if let Some(sni) = params.get("sni") {
        map.insert("sni".into(), url_decode(sni).into());
    }
    if let Some(cc) = params.get("congestion_control") {
        map.insert("congestion-controller".into(), (*cc).into());
    }
    Some(Value::Mapping(map))
}

/// SSR 链接格式: ssr://base64(host:port:protocol:method:obfs:base64(password)/?remarks=base64(name)&protoparam=base64(val)&obfsparam=base64(val))
fn parse_ssr(rest: &str, name: &str) -> Option<Value> {
    let decoded = flexible_base64_decode(rest).and_then(|b| String::from_utf8(b).ok())?;
    // 分离路径和查询参数
    let (path, query) = match decoded.split_once('/').or_else(|| decoded.split_once('?')) {
        Some((p, q)) => (p, q),
        None => (decoded.as_str(), ""),
    };
    let fields: Vec<&str> = path.split(':').collect();
    if fields.len() < 6 {
        return None;
    }
    let host = fields[0];
    let port = fields[1].parse::<u32>().ok()?;
    let protocol = fields[2];
    let method = fields[3];
    let obfs = fields[4];
    let password = flexible_base64_decode(fields[5])
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| fields[5].to_string());

    let params: std::collections::HashMap<&str, &str> =
        query.split('&').filter_map(|p| p.split_once('=')).collect();

    // 提取节点名称: remarks 字段优先
    if let Some(remarks_b64) = params.get("remarks") {
        if let Some(remarks) =
            flexible_base64_decode(remarks_b64).and_then(|b| String::from_utf8(b).ok())
        {
            if !remarks.trim().is_empty() {
                // 使用 remarks 作为名称（但 name 已由外层传入）
            }
        }
    }

    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "ssr".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.into());
    map.insert("cipher".into(), ssr_cipher(method).into());
    map.insert("password".into(), password.into());
    if protocol != "origin" {
        map.insert("protocol".into(), protocol.into());
        if let Some(pp) = params.get("protoparam") {
            let decoded_pp = flexible_base64_decode(pp)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            if !decoded_pp.is_empty() {
                map.insert("protocol-param".into(), decoded_pp.into());
            }
        }
    }
    if obfs != "plain" {
        map.insert("obfs".into(), obfs.into());
        if let Some(op) = params.get("obfsparam") {
            let decoded_op = flexible_base64_decode(op)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            if !decoded_op.is_empty() {
                map.insert("obfs-param".into(), decoded_op.into());
            }
        }
    }
    Some(Value::Mapping(map))
}

/// Hysteria v1 链接格式: hysteria://host:port?protocol=udp&auth=base64(auth)&insecure=1&obfs=xor&obfsParam=val&up=mbps&down=mbps&peer=sni
fn parse_hysteria(rest: &str, name: &str) -> Option<Value> {
    let (hostport, query) = match rest.split_once('?') {
        Some((h, q)) => (h, q),
        None => (rest, ""),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let params: std::collections::HashMap<&str, &str> =
        query.split('&').filter_map(|p| p.split_once('=')).collect();

    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "hysteria".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.parse::<u32>().ok()?.into());
    if let Some(auth) = params.get("auth") {
        let decoded_auth = flexible_base64_decode(auth)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| auth.to_string());
        map.insert("auth-str".into(), decoded_auth.into());
    }
    if let Some(protocol) = params.get("protocol") {
        map.insert("protocol".into(), (*protocol).into());
    }
    if let Some(obfs) = params.get("obfs") {
        map.insert("obfs".into(), (*obfs).into());
    }
    if let Some(obfs_param) = params.get("obfsParam") {
        map.insert("obfs-param".into(), url_decode(obfs_param).into());
    }
    if let Some(up) = params.get("up") {
        map.insert("up".into(), url_decode(up).into());
    }
    if let Some(down) = params.get("down") {
        map.insert("down".into(), url_decode(down).into());
    }
    if let Some(peer) = params.get("peer") {
        map.insert("sni".into(), url_decode(peer).into());
    }
    if params.get("insecure").map(|v| *v == "1").unwrap_or(false) {
        map.insert("skip-cert-verify".into(), true.into());
    }
    Some(Value::Mapping(map))
}

/// SOCKS5 链接格式: socks://user:password@host:port 或 socks://host:port
fn parse_socks(rest: &str, name: &str) -> Option<Value> {
    let (hostport, username, password) = if let Some((userinfo, hostport)) = rest.split_once('@') {
        let (u, p) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        (hostport, url_decode(u), url_decode(p))
    } else {
        (rest, String::new(), String::new())
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "socks5".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.parse::<u32>().ok()?.into());
    if !username.is_empty() {
        map.insert("username".into(), username.into());
    }
    if !password.is_empty() {
        map.insert("password".into(), password.into());
    }
    Some(Value::Mapping(map))
}

/// HTTP/HTTPS 代理链接格式: http://user:password@host:port 或 http://host:port
fn parse_http_proxy(rest: &str, name: &str) -> Option<Value> {
    let (hostport, username, password) = if let Some((userinfo, hostport)) = rest.split_once('@') {
        let (u, p) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        (hostport, url_decode(u), url_decode(p))
    } else {
        (rest, String::new(), String::new())
    };
    // 去除尾部可能的查询参数
    let hostport = hostport.split('?').next().unwrap_or(hostport);
    let (host, port) = hostport.rsplit_once(':')?;
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "http".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.parse::<u32>().ok()?.into());
    if !username.is_empty() {
        map.insert("username".into(), username.into());
    }
    if !password.is_empty() {
        map.insert("password".into(), password.into());
    }
    Some(Value::Mapping(map))
}

/// 将 SSR 加密方式映射为 Mihomo 支持的 cipher 名称
fn ssr_cipher(method: &str) -> &str {
    match method {
        "none" => "dummy",
        other => other,
    }
}

/// 尝试将文本解析为 Clash YAML，成功时返回 (RefreshReport, payload)
fn try_parse_clash_yaml(text: &str) -> Result<Option<ProxyImport>, String> {
    if let Ok(yaml) = serde_yaml::from_str::<Value>(text) {
        let proxies = yaml
            .get("proxies")
            .and_then(Value::as_sequence)
            .map_or(0, Vec::len);
        let groups = yaml
            .get("proxy-groups")
            .and_then(Value::as_sequence)
            .map_or(0, Vec::len);
        if proxies > 0 || groups > 0 {
            let mut clean = serde_yaml::Mapping::new();
            if let Some(value) = yaml.get("proxies") {
                clean.insert(Value::String("proxies".into()), value.clone());
            }
            if let Some(value) = yaml.get("proxy-groups") {
                clean.insert(Value::String("proxy-groups".into()), value.clone());
            }
            let payload = serde_yaml::to_string(&clean).map_err(error)?;
            return Ok(Some(ProxyImport {
                report: ProxyImportReport {
                    detected_format: "clash".into(),
                    proxy_count: proxies,
                    group_count: groups,
                },
                payload,
            }));
        }
    }
    Ok(None)
}

/// 灵活的 base64 解码：依次尝试标准、URL-safe no-pad、标准 no-pad
fn flexible_base64_decode(input: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(input)
        .ok()
        .or_else(|| URL_SAFE_NO_PAD.decode(input).ok())
        .or_else(|| STANDARD.decode(input.trim_end_matches('=')).ok())
}

#[doc(hidden)]
pub fn url_decode(s: &str) -> String {
    // 先收集所有解码后的字节，再整体转换为 UTF-8 字符串
    // 旧实现逐字节 push 为 char，导致 UTF-8 多字节中文字符被拆散成乱码
    let mut bytes = Vec::with_capacity(s.len());
    let src = s.as_bytes();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&src[i + 1..i + 3]).unwrap_or(""), 16)
            {
                bytes.push(byte);
                i += 3;
                continue;
            }
        }
        bytes.push(src[i]);
        i += 1;
    }
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_proxy_uri_lists() {
        let imported = parse_proxy_payload("ss://YWVzLTEyOC1nY206dGVzdA==@example.com:8388#my-ss\nvless://550e8400-e29b-41d4-a716-446655440000@example.com:443?type=ws&path=%2F&security=tls#my-vless").unwrap();
        assert_eq!(imported.report.proxy_count, 2);
        assert_eq!(imported.report.detected_format, "clash");
        assert!(imported.payload.contains("my-ss"));
        assert!(imported.payload.contains("my-vless"));
    }

    #[test]
    fn strips_clash_dns_and_rules_from_proxy_payload() {
        let imported=parse_proxy_payload("proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\nrules:\n  - MATCH,DIRECT\ndns:\n  enable: true").unwrap();
        assert!(imported.payload.contains("proxies:"));
        assert!(!imported.payload.contains("rules:"));
        assert!(!imported.payload.contains("dns:"));
    }

    #[test]
    fn parses_ssr_uri() {
        let ssr_body = "1.2.3.4:443:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:dGVzdDEyMw/?remarks=5peg6Ieq5ZCN&protoparam=&obfsparam=";
        let ssr_b64 = URL_SAFE_NO_PAD.encode(ssr_body.as_bytes());
        let uri = format!("ssr://{ssr_b64}#MySSR");
        let mut idx = 1;
        let node = parse_single_uri(&uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "ssr");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "1.2.3.4");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 443);
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "test123");
        assert_eq!(
            node.get("protocol").unwrap().as_str().unwrap(),
            "auth_aes128_md5"
        );
        assert_eq!(
            node.get("obfs").unwrap().as_str().unwrap(),
            "tls1.2_ticket_auth"
        );
    }

    #[test]
    fn parses_hysteria_v1_uri() {
        let uri = "hysteria://1.2.3.4:8443?protocol=udp&auth=c2VjcmV0&insecure=1&obfs=xor&obfsParam=mypass&up=100&down=200&peer=my.server.com#MyHysteria";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "hysteria");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "1.2.3.4");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 8443);
        assert_eq!(node.get("auth-str").unwrap().as_str().unwrap(), "secret");
        assert_eq!(node.get("obfs").unwrap().as_str().unwrap(), "xor");
        assert_eq!(node.get("sni").unwrap().as_str().unwrap(), "my.server.com");
        assert!(node.get("skip-cert-verify").unwrap().as_bool().unwrap());
    }

    #[test]
    fn parses_socks5_uri() {
        let uri = "socks5://user:pass@proxy.example.com:1080#MySOCKS";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "socks5");
        assert_eq!(
            node.get("server").unwrap().as_str().unwrap(),
            "proxy.example.com"
        );
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 1080);
        assert_eq!(node.get("username").unwrap().as_str().unwrap(), "user");
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "pass");
    }

    #[test]
    fn parses_http_proxy_uri() {
        let uri = "http://YWRtaW46MTIzNA==@proxy.example.com:8080#MyHTTP";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "http");
        assert_eq!(
            node.get("server").unwrap().as_str().unwrap(),
            "proxy.example.com"
        );
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 8080);
    }

    #[test]
    fn parses_base64_encoded_clash_yaml() {
        let yaml = "proxies:\n  - {name: node1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: test}\nproxy-groups:\n  - {name: auto, type: url-test, proxies: [node1], url: 'https://www.gstatic.com/generate_204', interval: 300}\nrules:\n  - MATCH,DIRECT\ndns:\n  enable: true";
        let encoded = STANDARD.encode(yaml.as_bytes());
        let imported = parse_proxy_payload(&encoded).unwrap();
        assert_eq!(imported.report.detected_format, "clash");
        assert_eq!(imported.report.proxy_count, 1);
        assert_eq!(imported.report.group_count, 1);
        assert!(imported.payload.contains("node1"));
        assert!(!imported.payload.contains("rules:"));
        assert!(!imported.payload.contains("dns:"));
    }

    #[test]
    fn parses_mixed_uri_with_ssr_and_vless() {
        let ssr_body = "1.2.3.4:443:origin:aes-256-cfb:plain:dGVzdA/?remarks=5peg6Ieq";
        let ssr_b64 = URL_SAFE_NO_PAD.encode(ssr_body.as_bytes());
        let text = format!("ssr://{ssr_b64}#SSR节点\nvless://550e8400-e29b-41d4-a716-446655440000@example.com:443?type=ws&security=tls#VLESS节点");
        let imported = parse_proxy_payload(&text).unwrap();
        assert_eq!(imported.report.proxy_count, 2);
        assert!(imported.payload.contains("ssr"));
        assert!(imported.payload.contains("vless"));
    }

    #[test]
    fn parses_sip002_ss_uri() {
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#%E5%8D%81%E4%B9%9D%E5%A4%A797.61%25%20292.84GB";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).expect("should parse SIP002 SS URI");
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "ss");
        assert_eq!(
            node.get("server").unwrap().as_str().unwrap(),
            "www.g00gle.com"
        );
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 10086);
        assert_eq!(
            node.get("cipher").unwrap().as_str().unwrap(),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "6xf/tf-0");
    }

    #[test]
    fn parses_sip002_ss_subscription_batch() {
        let uris = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#Node1\nss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#Node2";
        let b64 = STANDARD.encode(uris.as_bytes());
        let imported = parse_proxy_payload(&b64).unwrap();
        assert_eq!(imported.report.proxy_count, 2);
        assert!(imported.payload.contains("Node1"));
        assert!(imported.payload.contains("Node2"));
        assert!(imported.payload.contains("type: ss"));
        assert!(imported.payload.contains("chacha20-ietf-poly1305"));
    }

    #[test]
    fn url_decode_handles_utf8_chinese_characters() {
        let decoded = url_decode("%E5%8D%81%E4%B9%9D%E5%A4%A797.61%25%20292.84GB");
        assert_eq!(decoded, "十九大97.61% 292.84GB");
        let decoded2 =
            url_decode("%E9%A6%99%E6%B8%AF%E6%BE%B3%E9%97%A8A01%20%7C%20IEPL%20%7C%20x2");
        assert_eq!(decoded2, "香港澳门A01 | IEPL | x2");
    }

    #[test]
    fn parse_ss_preserves_name_with_chinese_chars() {
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=test#%E9%A6%99%E6%B8%AF%E6%BE%B3%E9%97%A8A01";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("name").unwrap().as_str().unwrap(), "香港澳门A01");
        assert_eq!(
            node.get("server").unwrap().as_str().unwrap(),
            "www.g00gle.com"
        );
    }

    #[test]
    fn parse_single_uri_handles_hash_in_base64_password() {
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:cGFzcyN3b3Jk@example.com:8388#MyNode";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("name").unwrap().as_str().unwrap(), "MyNode");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "example.com");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 8388);
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "pass#word");
    }
}
