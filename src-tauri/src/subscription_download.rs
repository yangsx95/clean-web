use std::time::Duration;

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use reqwest::header::CONTENT_LENGTH;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use tauri::State;

use crate::{
    proxy_crypto::encrypt_proxy_payload,
    storage::AppState,
    subscriptions::{import_text, SubscriptionFormat},
};

const MAX_SUBSCRIPTION_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReport {
    pub detected_format: String,
    pub imported_count: usize,
    pub ignored_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
}

#[derive(Debug, Deserialize)]
struct SafeSearchManifest {
    version: u32,
    mappings: Vec<SafeSearchMapping>,
}

#[derive(Debug, Deserialize)]
struct SafeSearchMapping {
    domain: String,
    target: String,
}

#[tauri::command]
pub async fn refresh_subscription(
    id: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<RefreshReport, String> {
    state.require_session(&session_token)?;
    refresh_subscription_inner(id, &state).await
}

async fn refresh_subscription_inner(id: String, state: &AppState) -> Result<RefreshReport, String> {
    let (kind, url, configured_format, category) = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        db.query_row(
            "SELECT kind,url,format,COALESCE(category,'custom') FROM subscriptions WHERE id=?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|_| "订阅不存在")?
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("clash-verge/v2.0")
        .build()
        .map_err(error)?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|value| format!("订阅下载失败：{value}"))?;
    if !response.status().is_success() {
        return record_error(&state, &id, format!("服务器返回 {}", response.status()));
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|size| size > MAX_SUBSCRIPTION_BYTES)
    {
        return record_error(&state, &id, "订阅文件超过20MB限制".into());
    }
    let bytes = response.bytes().await.map_err(error)?;
    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return record_error(&state, &id, "订阅文件超过20MB限制".into());
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| "订阅不是有效UTF-8文本")?;

    let report = if kind == "rule" {
        refresh_rules(
            &state,
            &id,
            &url,
            configured_format.as_deref(),
            &category,
            &text,
        )?
    } else {
        let (report, payload) = parse_proxy_payload(&text)?;
        store_proxy_payload(state, &id, &report.detected_format, &payload)?;
        report
    };
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute("UPDATE subscriptions SET format=?1,last_updated_at=CURRENT_TIMESTAMP,last_error=NULL WHERE id=?2",params![report.detected_format,id]).map_err(error)?;
    drop(db);
    Ok(report)
}

fn store_proxy_payload(
    state: &AppState,
    id: &str,
    detected_format: &str,
    payload: &str,
) -> Result<(), String> {
    let encrypted_payload = encrypt_proxy_payload(payload)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute("INSERT INTO proxy_payloads(subscription_id,format,payload,updated_at) VALUES(?1,?2,?3,CURRENT_TIMESTAMP) ON CONFLICT(subscription_id) DO UPDATE SET format=excluded.format,payload=excluded.payload,updated_at=CURRENT_TIMESTAMP",params![id,detected_format,encrypted_payload]).map_err(error)?;
    Ok(())
}

#[tauri::command]
pub async fn refresh_due_subscriptions(state: State<'_, AppState>) -> Result<usize, String> {
    let due = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        let mut statement=db.prepare("SELECT id FROM subscriptions WHERE enabled=1 AND update_interval_hours IS NOT NULL AND (last_updated_at IS NULL OR datetime(last_updated_at, '+' || update_interval_hours || ' hours') <= CURRENT_TIMESTAMP)").map_err(error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(error)?;
        rows
    };
    let mut updated = 0;
    for id in due {
        if refresh_subscription_inner(id, &state).await.is_ok() {
            updated += 1;
        }
    }
    Ok(updated)
}

fn refresh_rules(
    state: &AppState,
    id: &str,
    url: &str,
    configured: Option<&str>,
    category: &str,
    text: &str,
) -> Result<RefreshReport, String> {
    let format = match configured.filter(|value| *value != "auto") {
        Some(value) => parse_format(value)?,
        None => detect_rule_format(text),
    };
    if format == SubscriptionFormat::SafeSearch {
        return refresh_safe_search(state, id, text);
    }
    let imported = import_text(format, text, id, url, category);
    let mut db = state.db.lock().map_err(|_| "数据库不可用")?;
    let tx = db.transaction().map_err(error)?;
    tx.execute(
        "DELETE FROM imported_rules WHERE subscription_id=?1",
        params![id],
    )
    .map_err(error)?;
    for item in &imported.rules {
        tx.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,item.rule.id,format!("{:?}",item.rule.kind),item.rule.pattern,format!("{:?}",item.rule.action),item.rule.category,item.source.source_line as i64]).map_err(error)?;
    }
    tx.commit().map_err(error)?;
    Ok(RefreshReport {
        detected_format: format_name(format).into(),
        imported_count: imported.rules.len(),
        ignored_count: imported.ignored.len(),
        proxy_count: 0,
        group_count: 0,
    })
}

fn refresh_safe_search(state: &AppState, id: &str, text: &str) -> Result<RefreshReport, String> {
    let manifest: SafeSearchManifest = serde_yaml::from_str(text)
        .map_err(|value| format!("安全搜索订阅不是有效 YAML：{value}"))?;
    if manifest.version != 1 || manifest.mappings.is_empty() {
        return Err("安全搜索订阅版本无效或没有映射".into());
    }
    let allowed_targets = [
        "forcesafesearch.google.com",
        "strict.bing.com",
        "safe.duckduckgo.com",
        "restrict.youtube.com",
        "restrictmoderate.youtube.com",
        "familysearch.yandex.ru",
        "strict.search.yahoo.com",
    ];
    let mut normalized = Vec::new();
    for (index, mapping) in manifest.mappings.into_iter().enumerate() {
        let domain = mapping.domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let target = mapping.target.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty()
            || !domain.contains('.')
            || domain.contains(['/', ':', ' '])
            || !allowed_targets.contains(&target.as_str())
        {
            return Err(format!("安全搜索订阅第 {} 条映射无效", index + 1));
        }
        normalized.push((domain, target, index as i64 + 1));
    }
    let mut db = state.db.lock().map_err(|_| "数据库不可用")?;
    let tx = db.transaction().map_err(error)?;
    tx.execute(
        "DELETE FROM safe_search_mappings WHERE subscription_id=?1",
        params![id],
    )
    .map_err(error)?;
    for (domain, target, source_line) in &normalized {
        tx.execute(
            "INSERT INTO safe_search_mappings(subscription_id,domain,target,source_line) VALUES(?1,?2,?3,?4)",
            params![id, domain, target, source_line],
        )
        .map_err(error)?;
    }
    tx.commit().map_err(error)?;
    Ok(RefreshReport {
        detected_format: "safe-search".into(),
        imported_count: normalized.len(),
        ignored_count: 0,
        proxy_count: 0,
        group_count: 0,
    })
}

fn parse_proxy_payload(text: &str) -> Result<(RefreshReport, String), String> {
    // 尝试直接解析为 Clash YAML
    if let Some(result) = try_parse_clash_yaml(text)? {
        return Ok(result);
    }
    // 尝试 base64 解码（很多订阅商会把整个 Clash 配置 base64 后返回）
    if let Some(decoded) = flexible_base64_decode(text.trim())
        .and_then(|s| String::from_utf8(s).ok())
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
    clean.insert(
        Value::String("proxies".into()),
        Value::Sequence(proxies),
    );
    let payload = serde_yaml::to_string(&clean).map_err(error)?;
    Ok((
        RefreshReport {
            detected_format: "clash".into(),
            imported_count: 0,
            ignored_count: 0,
            proxy_count: count,
            group_count: 0,
        },
        payload,
    ))
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

fn parse_single_uri(uri: &str, index: &mut usize) -> Option<Value> {
    // 分离 fragment (节点名称)
    // 只在 '@' 之后查找 '#'，避免 base64 密码中的 '#' 被错误识别为 fragment 分隔符
    let (main, name) = {
        let at_pos = uri.find('@');
        let search_start = at_pos.map(|p| p + 1).unwrap_or(0);
        match uri[search_start..].rfind('#') {
            Some(rel_pos) => {
                let abs_pos = search_start + rel_pos;
                (&uri[..abs_pos], url_decode(&uri[abs_pos + 1..].replace('+', " ")))
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
    if let Some(rest) = main.strip_prefix("socks5://").or_else(|| main.strip_prefix("socks://")) {
        return parse_socks(rest, &name);
    }
    if let Some(rest) = main.strip_prefix("http://").or_else(|| main.strip_prefix("https://")) {
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
        let decoded = flexible_base64_decode(rest)
            .and_then(|b| String::from_utf8(b).ok())?;
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
    if map.get("server").is_none() {
        return None;
    }
    Some(Value::Mapping(map))
}

fn parse_vmess(rest: &str, name: &str) -> Option<Value> {
    let decoded = flexible_base64_decode(rest)
        .and_then(|b| String::from_utf8(b).ok())?;
    let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;
    let get = |k: &str| json.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "vmess".into());
    map.insert("server".into(), get("add").into());
    map.insert("port".into(), get("port").parse::<u32>().ok()?.into());
    map.insert("uuid".into(), get("id").into());
    map.insert("alterId".into(), get("aid").parse::<u32>().unwrap_or(0).into());
    let scy = get("scy");
    map.insert("cipher".into(), (if scy.is_empty() { "auto" } else { scy }).into());
    let network = get("net");
    if !network.is_empty() {
        map.insert("network".into(), network.into());
    }
    if network == "ws" || network == "h2" || network == "grpc" {
        if !get("path").is_empty() {
            map.insert(format!("{}-opts", network).as_str().into(), {
                let mut opts = serde_yaml::Mapping::new();
                opts.insert("path".into(), get("path").into());
                if !get("host").is_empty() {
                    opts.insert("headers".into(), {
                        let mut h = serde_yaml::Mapping::new();
                        h.insert("Host".into(), get("host").into());
                        h
                    }.into());
                }
                opts
            }.into());
        }
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
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .collect();

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
                opts.insert("headers".into(), {
                    let mut h = serde_yaml::Mapping::new();
                    h.insert("Host".into(), url_decode(host).into());
                    h
                }.into());
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
        if params.get("allowInsecure").map(|v| *v == "1").unwrap_or(false) {
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
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .collect();
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
    let decoded = flexible_base64_decode(rest)
        .and_then(|b| String::from_utf8(b).ok())?;
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

    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .collect();

    // 提取节点名称: remarks 字段优先
    if let Some(remarks_b64) = params.get("remarks") {
        if let Some(remarks) = flexible_base64_decode(remarks_b64)
            .and_then(|b| String::from_utf8(b).ok())
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
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .collect();

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
fn try_parse_clash_yaml(text: &str) -> Result<Option<(RefreshReport, String)>, String> {
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
            return Ok(Some((
                RefreshReport {
                    detected_format: "clash".into(),
                    imported_count: 0,
                    ignored_count: 0,
                    proxy_count: proxies,
                    group_count: groups,
                },
                payload,
            )));
        }
    }
    Ok(None)
}

/// 灵活的 base64 解码：依次尝试标准、URL-safe no-pad、标准 no-pad
fn flexible_base64_decode(input: &str) -> Option<Vec<u8>> {
    STANDARD.decode(input).ok()
        .or_else(|| URL_SAFE_NO_PAD.decode(input).ok())
        .or_else(|| STANDARD.decode(input.trim_end_matches('=')).ok())
}

fn url_decode(s: &str) -> String {
    // 先收集所有解码后的字节，再整体转换为 UTF-8 字符串
    // 旧实现逐字节 push 为 char，导致 UTF-8 多字节中文字符被拆散成乱码
    let mut bytes = Vec::with_capacity(s.len());
    let src = s.as_bytes();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let Ok(byte) = u8::from_str_radix(
                &std::str::from_utf8(&src[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                bytes.push(byte);
                i += 3;
                continue;
            }
        }
        bytes.push(src[i]);
        i += 1;
    }
    String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn detect_rule_format(text: &str) -> SubscriptionFormat {
    if text.contains("mappings:") && text.contains("target:") {
        return SubscriptionFormat::SafeSearch;
    }
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', '!']))
        .take(30)
        .collect();
    if text.contains("payload:")
        || lines
            .iter()
            .any(|line| line.starts_with("DOMAIN,") || line.starts_with("DOMAIN-SUFFIX,"))
    {
        return SubscriptionFormat::Clash;
    }
    if lines
        .iter()
        .any(|line| line.starts_with("||") || line.contains("##"))
    {
        return SubscriptionFormat::Adblock;
    }
    if lines.iter().all(|line| {
        line.parse::<std::net::IpAddr>().is_ok() || line.parse::<ipnet::IpNet>().is_ok()
    }) {
        return SubscriptionFormat::IpList;
    }
    if lines.iter().any(|line| {
        line.split_whitespace().count() >= 2
            && line
                .split_whitespace()
                .next()
                .is_some_and(|v| v.parse::<std::net::IpAddr>().is_ok())
    }) {
        return SubscriptionFormat::Hosts;
    }
    SubscriptionFormat::DomainList
}
fn parse_format(value: &str) -> Result<SubscriptionFormat, String> {
    match value {
        "clash" => Ok(SubscriptionFormat::Clash),
        "hosts" => Ok(SubscriptionFormat::Hosts),
        "domain-list" => Ok(SubscriptionFormat::DomainList),
        "ip-list" => Ok(SubscriptionFormat::IpList),
        "adblock" => Ok(SubscriptionFormat::Adblock),
        "safe-search" => Ok(SubscriptionFormat::SafeSearch),
        _ => Err("不支持的订阅格式".into()),
    }
}
fn format_name(value: SubscriptionFormat) -> &'static str {
    match value {
        SubscriptionFormat::Clash => "clash",
        SubscriptionFormat::Hosts => "hosts",
        SubscriptionFormat::DomainList => "domain-list",
        SubscriptionFormat::IpList => "ip-list",
        SubscriptionFormat::Adblock => "adblock",
        SubscriptionFormat::SafeSearch => "safe-search",
    }
}
fn record_error<T>(state: &AppState, id: &str, message: String) -> Result<T, String> {
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "UPDATE subscriptions SET last_error=?1 WHERE id=?2",
            params![message, id],
        );
    }
    Err(message)
}
fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_crypto::{
        decrypt_proxy_payload, is_encrypted_proxy_payload, test_key_env_lock,
    };
    use rusqlite::params;
    #[test]
    fn detects_common_rule_formats() {
        assert_eq!(
            detect_rule_format("||ads.example^"),
            SubscriptionFormat::Adblock
        );
        assert_eq!(
            detect_rule_format("DOMAIN-SUFFIX,bad.example,REJECT"),
            SubscriptionFormat::Clash
        );
        assert_eq!(
            detect_rule_format("203.0.113.0/24"),
            SubscriptionFormat::IpList
        );
    }
    #[test]
    fn imports_validated_safe_search_manifest() {
        let state = AppState::open(":memory:").unwrap();
        state.db.lock().unwrap().execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('safe','rule','safe','https://example.test/safe.yaml',1)",[]).unwrap();
        let report = refresh_safe_search(
            &state,
            "safe",
            "version: 1\nmappings:\n  - domain: search.example.com\n    target: forcesafesearch.google.com\n",
        )
        .unwrap();
        assert_eq!(report.imported_count, 1);
        let count: i64 = state.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM safe_search_mappings WHERE subscription_id='safe' AND domain='search.example.com'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn counts_proxy_uri_lists() {
        let (report, payload) = parse_proxy_payload("ss://YWVzLTEyOC1nY206dGVzdA==@example.com:8388#my-ss\nvless://550e8400-e29b-41d4-a716-446655440000@example.com:443?type=ws&path=%2F&security=tls#my-vless").unwrap();
        assert_eq!(report.proxy_count, 2);
        assert_eq!(report.detected_format, "clash");
        assert!(payload.contains("my-ss"));
        assert!(payload.contains("my-vless"));
    }
    #[test]
    fn strips_clash_dns_and_rules_from_proxy_payload() {
        let (_,payload)=parse_proxy_payload("proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\nrules:\n  - MATCH,DIRECT\ndns:\n  enable: true").unwrap();
        assert!(payload.contains("proxies:"));
        assert!(!payload.contains("rules:"));
        assert!(!payload.contains("dns:"));
    }

    #[test]
    fn store_proxy_payload_encrypts_payload() {
        let _guard = test_key_env_lock();
        std::env::set_var(
            "CLEANWEB_TEST_PROXY_KEY_B64",
            base64::engine::general_purpose::STANDARD.encode([9_u8; 32]),
        );
        let state = AppState::open(":memory:").unwrap();
        let id = "proxy-a";
        let proxy_text = "proxies:\n  - {name: a, password: secret-token}\n";
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,update_interval_hours) VALUES(?1,'proxy','Proxy','https://example.test/sub.yaml',24)",params![id]).unwrap();
        }

        store_proxy_payload(&state, id, "clash", proxy_text).unwrap();

        let stored: String = {
            let db = state.db.lock().unwrap();
            db.query_row(
                "SELECT payload FROM proxy_payloads WHERE subscription_id=?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(is_encrypted_proxy_payload(&stored));
        assert!(!stored.contains("secret-token"));
        assert!(decrypt_proxy_payload(&stored)
            .unwrap()
            .contains("secret-token"));
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }

    #[test]
    fn parses_ssr_uri() {
        // ssr://host:port:protocol:method:obfs:base64(password)/?remarks=base64(name)&protoparam=base64(val)&obfsparam=base64(val)
        // host=1.2.3.4, port=443, protocol=auth_aes128_md5, method=aes-256-cfb, obfs=tls1.2_ticket_auth, password=test123
        let ssr_body = "1.2.3.4:443:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:dGVzdDEyMw/?remarks=5peg6Ieq5ZCN&protoparam=&obfsparam=";
        let ssr_b64 = URL_SAFE_NO_PAD.encode(ssr_body.as_bytes());
        let uri = format!("ssr://{ssr_b64}#MySSR");
        let mut idx = 1;
        let node = parse_single_uri(&uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "ssr");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "1.2.3.4");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 443);
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "test123");
        assert_eq!(node.get("protocol").unwrap().as_str().unwrap(), "auth_aes128_md5");
        assert_eq!(node.get("obfs").unwrap().as_str().unwrap(), "tls1.2_ticket_auth");
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
        assert_eq!(node.get("skip-cert-verify").unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn parses_socks5_uri() {
        let uri = "socks5://user:pass@proxy.example.com:1080#MySOCKS";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "socks5");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "proxy.example.com");
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
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "proxy.example.com");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 8080);
    }

    #[test]
    fn parses_base64_encoded_clash_yaml() {
        let yaml = "proxies:\n  - {name: node1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: test}\nproxy-groups:\n  - {name: auto, type: url-test, proxies: [node1], url: 'https://www.gstatic.com/generate_204', interval: 300}\nrules:\n  - MATCH,DIRECT\ndns:\n  enable: true";
        let encoded = STANDARD.encode(yaml.as_bytes());
        let (report, payload) = parse_proxy_payload(&encoded).unwrap();
        assert_eq!(report.detected_format, "clash");
        assert_eq!(report.proxy_count, 1);
        assert_eq!(report.group_count, 1);
        assert!(payload.contains("node1"));
        assert!(!payload.contains("rules:"));
        assert!(!payload.contains("dns:"));
    }

    #[test]
    fn parses_mixed_uri_with_ssr_and_vless() {
        let ssr_body = "1.2.3.4:443:origin:aes-256-cfb:plain:dGVzdA/?remarks=5peg6Ieq";
        let ssr_b64 = URL_SAFE_NO_PAD.encode(ssr_body.as_bytes());
        let text = format!("ssr://{ssr_b64}#SSR节点\nvless://550e8400-e29b-41d4-a716-446655440000@example.com:443?type=ws&security=tls#VLESS节点");
        let (report, payload) = parse_proxy_payload(&text).unwrap();
        assert_eq!(report.proxy_count, 2);
        assert!(payload.contains("ssr"));
        assert!(payload.contains("vless"));
    }

    #[test]
    fn parses_sip002_ss_uri() {
        // SIP002 format: ss://method_b64:password_b64@host:port/?group=GROUP#NAME
        // Uses exact base64 from real subscription data
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#%E5%8D%81%E4%B9%9D%E5%A4%A797.61%25%20292.84GB";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).expect("should parse SIP002 SS URI");
        assert_eq!(node.get("type").unwrap().as_str().unwrap(), "ss");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "www.g00gle.com");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 10086);
        assert_eq!(node.get("cipher").unwrap().as_str().unwrap(), "chacha20-ietf-poly1305");
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "6xf/tf-0");
    }

    #[test]
    fn parses_sip002_ss_subscription_batch() {
        // Simulate a base64-encoded batch of SIP002 ss:// URIs (like sub=2)
        let uris = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#Node1\nss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=aUt1dXUgVlBO#Node2";
        let b64 = STANDARD.encode(uris.as_bytes());
        let (report, payload) = parse_proxy_payload(&b64).unwrap();
        assert_eq!(report.proxy_count, 2);
        assert!(payload.contains("Node1"));
        assert!(payload.contains("Node2"));
        assert!(payload.contains("type: ss"));
        assert!(payload.contains("chacha20-ietf-poly1305"));
    }

    #[test]
    fn url_decode_handles_utf8_chinese_characters() {
        // UTF-8 multi-byte: 十 = E5 8D 81, 九 = E4 B9 9D, 大 = E5 A4 A7
        let decoded = url_decode("%E5%8D%81%E4%B9%9D%E5%A4%A797.61%25%20292.84GB");
        assert_eq!(decoded, "十九大97.61% 292.84GB");
        // 香港澳门A01 | IEPL | x2
        let decoded2 = url_decode("%E9%A6%99%E6%B8%AF%E6%BE%B3%E9%97%A8A01%20%7C%20IEPL%20%7C%20x2");
        assert_eq!(decoded2, "香港澳门A01 | IEPL | x2");
    }

    #[test]
    fn parse_ss_preserves_name_with_chinese_chars() {
        // SS URI with Chinese name in fragment
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:NnhmL3RmLTA=@www.g00gle.com:10086/?group=test#%E9%A6%99%E6%B8%AF%E6%BE%B3%E9%97%A8A01";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("name").unwrap().as_str().unwrap(), "香港澳门A01");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "www.g00gle.com");
    }

    #[test]
    fn parse_single_uri_handles_hash_in_base64_password() {
        // Base64 of "pass#word" is cGFzcyN3b3Jk — contains '#' which is valid in base64
        // URI: ss://method_b64:password_with_hash_b64@host:port#name
        // The '#' in password_b64 must NOT be confused with the fragment '#'
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ==:cGFzcyN3b3Jk@example.com:8388#MyNode";
        let mut idx = 1;
        let node = parse_single_uri(uri, &mut idx).unwrap();
        assert_eq!(node.get("name").unwrap().as_str().unwrap(), "MyNode");
        assert_eq!(node.get("server").unwrap().as_str().unwrap(), "example.com");
        assert_eq!(node.get("port").unwrap().as_u64().unwrap(), 8388);
        assert_eq!(node.get("password").unwrap().as_str().unwrap(), "pass#word");
    }
}
