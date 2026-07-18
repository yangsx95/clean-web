//! Xray policy-front configuration.
//!
//! Xray owns TUN and SafeSearch DNS rewriting. Mihomo remains the transport
//! backend so CleanWeb keeps Clash subscription and protocol compatibility.

use flate2::read::GzDecoder;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Manager};

use crate::{
    mihomo::SafeSearchMapping,
    rules::{wildcard_regex, Action, CompiledRule, MatcherKind, RuleInput},
};

pub const MIHOMO_TRANSPORT_PORT: u16 = 17890;

#[cfg(target_os = "macos")]
const ACCESS_LOG: &str = "/Library/Application Support/CleanWeb/xray-access.log";
#[cfg(not(target_os = "macos"))]
const ACCESS_LOG: &str = "xray-access.log";

#[cfg(target_arch = "aarch64")]
const CORE_ASSET: &str = "xray-macos-arm64-v26.3.27.gz";
#[cfg(target_arch = "aarch64")]
const CORE_SHA256: &str = "932e69dadd1c2fb1f17b24e17fb44c0101d7285678129c95d6133531fa792383";
#[cfg(target_arch = "x86_64")]
const CORE_ASSET: &str = "xray-macos-amd64-v26.3.27.gz";
#[cfg(target_arch = "x86_64")]
const CORE_SHA256: &str = "e6d12f96b606a74ac90c9e3ad56f53b5e3e0d64bf90d0c2789586ffd883ac5f3";

/// Extracts the pinned, checksum-verified Xray resource. Xray remains a
/// separate MPL-2.0 executable and is never downloaded or self-updated at
/// runtime.
pub fn ensure_binary(app: &AppHandle, runtime: &Path) -> Result<PathBuf, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, runtime);
        return Err("Xray policy core is currently packaged only for macOS".into());
    }
    #[cfg(target_os = "macos")]
    {
        fs::create_dir_all(runtime).map_err(|value| value.to_string())?;
        let output = runtime.join("xray");
        if output.is_file() {
            return Ok(output);
        }
        let resource = app
            .path()
            .resource_dir()
            .map_err(|value| value.to_string())?
            .join("resources/xray")
            .join(CORE_ASSET);
        let bytes = fs::read(&resource).map_err(|value| {
            format!("缺少官方 Xray 策略内核资源 {}：{value}", resource.display())
        })?;
        if format!("{:x}", Sha256::digest(&bytes)) != CORE_SHA256 {
            return Err("Xray 策略内核校验失败".into());
        }
        let mut decoder = GzDecoder::new(bytes.as_slice());
        let mut file = File::create(&output).map_err(|value| value.to_string())?;
        io::copy(&mut decoder, &mut file).map_err(|value| value.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))
            .map_err(|value| value.to_string())?;
        Ok(output)
    }
}

pub(crate) fn build_policy_config(
    mappings: &[SafeSearchMapping],
    policy_rules: &[RuleInput],
    proxy_enabled: bool,
    transport_user: &str,
    transport_password: &str,
    tun_name: &str,
) -> Result<String, String> {
    let transport_tag = if proxy_enabled { "mihomo" } else { "direct" };
    let mut hosts = Map::new();
    let mut safe_domains = Vec::new();
    for mapping in mappings {
        // Xray's DNS hosts object accepts exact domain aliases. Wildcards stay
        // in the subscription model but cannot be represented as a DNS CNAME.
        if mapping.domain.contains('*') {
            continue;
        }
        hosts.insert(
            mapping.domain.clone(),
            Value::String(mapping.target.clone()),
        );
        safe_domains.push(format!("full:{}", mapping.domain));
    }

    #[allow(unused_mut)]
    let mut tun_settings = json!({
        "name": tun_name,
        "mtu": 1500,
        "gateway": ["169.254.10.1/30"],
        "autoOutboundsInterface": "auto"
    });
    #[cfg(target_os = "windows")]
    {
        tun_settings["name"] = Value::String("CleanWeb".into());
        tun_settings["desc"] = Value::String("CleanWeb".into());
        tun_settings["dns"] = json!(["1.1.1.1", "8.8.8.8"]);
        tun_settings["autoSystemRoutingTable"] = json!(["0.0.0.0/0", "::/0"]);
    }

    let mut routing_rules = vec![
        json!({
            "type": "field",
            "inboundTag": ["cleanweb-dns-in"],
            "network": "tcp,udp",
            "outboundTag": "dns-out"
        }),
        json!({
            "type": "field",
            "inboundTag": ["cleanweb-tun"],
            "port": 53,
            "network": "tcp,udp",
            "outboundTag": "dns-out"
        }),
        json!({
            "type": "field",
            "inboundTag": ["cleanweb-dns"],
            "network": "tcp",
            "outboundTag": transport_tag
        }),
    ];

    // Policy comes first so an explicitly blacklisted IP is never forwarded,
    // including a literal connection to an address on a local network.
    routing_rules.extend(compile_policy_rules(policy_rules, transport_tag)?);

    // Unmatched local networks are a product-integrity exception and remain
    // direct so routers and printers do not travel through a remote proxy.
    routing_rules.push(json!({
        "type": "field",
        "ip": [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
            "::1/128", "fc00::/7", "fe80::/10"
        ],
        "outboundTag": "direct"
    }));

    // Prevent browsers from bypassing CleanWeb's DNS policy with a known DoH
    // endpoint whenever SafeSearch enforcement is active.
    if !mappings.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "domain": [
                "domain:dns.google", "full:cloudflare-dns.com",
                "full:mozilla.cloudflare-dns.com", "full:doh.opendns.com",
                "full:dns.quad9.net", "full:dns.nextdns.io"
            ],
            "outboundTag": "blocked"
        }));
    }
    if !safe_domains.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "domain": safe_domains,
            "network": "tcp,udp",
            "outboundTag": if proxy_enabled { "safe-via-mihomo" } else { "safe-direct" }
        }));
    }
    routing_rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": transport_tag
    }));

    let config = json!({
        "log": {
            "access": ACCESS_LOG,
            "loglevel": "info"
        },
        "dns": {
            "hosts": hosts,
            "servers": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query"
            ],
            "queryStrategy": "UseIP",
            "useSystemHosts": false,
            "tag": "cleanweb-dns"
        },
        "inbounds": [
            {
                "tag": "cleanweb-dns-in",
                "listen": "127.0.0.1",
                "port": 53,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "1.1.1.1",
                    "port": 53,
                    "network": "tcp,udp"
                }
            },
            {
                "tag": "cleanweb-tun",
                "protocol": "tun",
                "settings": tun_settings,
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": false
                }
            }
        ],
        "outbounds": [
            {
                "tag": "dns-out",
                "protocol": "dns"
            },
            {
                "tag": "mihomo",
                "protocol": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": MIHOMO_TRANSPORT_PORT,
                    "user": transport_user,
                    "pass": transport_password
                }
            },
            {
                "tag": "safe-via-mihomo",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "ForceIP"
                },
                "streamSettings": {
                    "sockopt": {
                        "dialerProxy": "mihomo"
                    }
                }
            },
            {
                "tag": "safe-direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "ForceIP"
                }
            },
            {
                "tag": "blocked",
                "protocol": "blackhole",
                "settings": {
                    "response": { "type": "none" }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIP"
                }
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules
        }
    });
    serde_json::to_string_pretty(&config).map_err(|value| value.to_string())
}

fn compile_policy_rules(
    inputs: &[RuleInput],
    allowed_outbound: &str,
) -> Result<Vec<Value>, String> {
    use std::collections::{BTreeMap, BTreeSet};

    // Grouping keeps large community subscriptions compact without changing
    // priority. Allow/Proxy and Block are deliberately kept in separate rules.
    let mut groups: BTreeMap<(u16, u8, u8), BTreeSet<String>> = BTreeMap::new();
    for input in inputs {
        let compiled = CompiledRule::compile(input.clone())
            .map_err(|value| format!("规则 {} 无效：{value}", input.id))?;
        let source = compiled.source;
        let (field, value) = match source.kind {
            MatcherKind::Exact => (0, format!("full:{}", source.pattern)),
            MatcherKind::Suffix => (0, format!("domain:{}", source.pattern)),
            MatcherKind::Contains => (0, format!("keyword:{}", source.pattern)),
            MatcherKind::Wildcard => (
                0,
                format!(
                    "regexp:(?i){}",
                    wildcard_regex(&source.pattern)
                        .map_err(|value| format!("规则 {} 无效：{value}", source.id))?
                        .as_str()
                ),
            ),
            MatcherKind::Regex => (0, format!("regexp:(?i){}", source.pattern)),
            MatcherKind::Ip => {
                let ip: std::net::IpAddr = source
                    .pattern
                    .parse()
                    .map_err(|_| format!("规则 {} 的 IP 无效", source.id))?;
                (1, format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
            }
            MatcherKind::Cidr => (1, source.pattern),
        };
        let action = if source.action == Action::Block { 0 } else { 1 };
        groups
            .entry((source.priority, action, field))
            .or_default()
            .insert(value);
    }

    Ok(groups
        .into_iter()
        .map(|((_priority, action, field), values)| {
            let mut rule = Map::new();
            rule.insert("type".into(), Value::String("field".into()));
            rule.insert(
                if field == 0 { "domain" } else { "ip" }.into(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
            rule.insert(
                "outboundTag".into(),
                Value::String(
                    if action == 0 {
                        "blocked"
                    } else {
                        allowed_outbound
                    }
                    .into(),
                ),
            );
            Value::Object(rule)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Read, process::Command};

    #[test]
    #[cfg(target_os = "macos")]
    fn bundled_core_matches_the_pinned_checksum_and_contains_a_macho_binary() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources/xray")
            .join(CORE_ASSET);
        let bytes = fs::read(path).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), CORE_SHA256);
        let mut decoder = GzDecoder::new(bytes.as_slice());
        let mut magic = [0_u8; 4];
        decoder.read_exact(&mut magic).unwrap();
        assert!(matches!(
            magic,
            [0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf]
        ));
    }

    #[test]
    fn safe_search_is_resolved_by_xray_before_mihomo_transport() {
        let config = build_policy_config(
            &[
                SafeSearchMapping {
                    domain: "www.google.com".into(),
                    target: "forcesafesearch.google.com".into(),
                },
                SafeSearchMapping {
                    domain: "www.google.*".into(),
                    target: "forcesafesearch.google.com".into(),
                },
            ],
            &[],
            true,
            "cleanweb",
            "secret",
            "utun233",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(
            value.pointer("/dns/hosts/www.google.com"),
            Some(&Value::String("forcesafesearch.google.com".into()))
        );
        assert!(value.pointer("/dns/hosts/www.google.*").is_none());
        assert_eq!(
            value.pointer("/outbounds/2/settings/domainStrategy"),
            Some(&Value::String("ForceIP".into()))
        );
        assert_eq!(
            value.pointer("/outbounds/2/streamSettings/sockopt/dialerProxy"),
            Some(&Value::String("mihomo".into()))
        );
        assert_eq!(
            value.pointer("/outbounds/1/settings/port"),
            Some(&Value::from(MIHOMO_TRANSPORT_PORT))
        );
    }

    #[test]
    fn dns_queries_are_captured_before_the_default_transport_rule() {
        let config = build_policy_config(&[], &[], true, "cleanweb", "secret", "utun233").unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();
        let rules = value.pointer("/routing/rules").unwrap().as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"], json!(["cleanweb-dns-in"]));
        assert_eq!(rules[0]["outboundTag"], Value::String("dns-out".into()));
        assert_eq!(rules[1]["port"], Value::from(53));
        assert_eq!(rules[1]["outboundTag"], Value::String("dns-out".into()));
        assert_eq!(
            rules[2]["inboundTag"],
            json!(["cleanweb-dns"]),
            "Xray 自身的上游 DNS 请求必须经过受控 Mihomo 传输"
        );
        assert_eq!(rules[2]["outboundTag"], Value::String("mihomo".into()));
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["port"], 53);
        assert!(value["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|server| !server.as_str().unwrap().contains("+local")));
        assert_eq!(
            rules.last().unwrap()["outboundTag"],
            Value::String("mihomo".into())
        );
    }

    #[test]
    fn proxy_off_keeps_filtering_but_uses_xray_direct_outbound() {
        let config = build_policy_config(
            &[SafeSearchMapping {
                domain: "www.google.com".into(),
                target: "forcesafesearch.google.com".into(),
            }],
            &[RuleInput {
                id: "allow".into(),
                action: Action::Allow,
                priority: 40,
                kind: MatcherKind::Suffix,
                pattern: "example.com".into(),
                category: "custom".into(),
            }],
            false,
            "cleanweb",
            "secret",
            "utun233",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();
        let rules = value["routing"]["rules"].as_array().unwrap();

        assert_eq!(rules[2]["outboundTag"], "direct");
        assert!(rules.iter().any(|rule| {
            rule["domain"]
                .as_array()
                .is_some_and(|domains| domains.contains(&json!("domain:example.com")))
                && rule["outboundTag"] == "direct"
        }));
        assert!(rules
            .iter()
            .any(|rule| rule["outboundTag"] == "safe-direct"));
        assert_eq!(rules.last().unwrap()["outboundTag"], "direct");
    }

    #[test]
    fn content_policy_is_compiled_before_safe_search_and_transport() {
        let policy = vec![
            RuleInput {
                id: "parent:block".into(),
                action: Action::Block,
                priority: 30,
                kind: MatcherKind::Suffix,
                pattern: "baidu.com".into(),
                category: "custom".into(),
            },
            RuleInput {
                id: "parent:allow".into(),
                action: Action::Allow,
                priority: 40,
                kind: MatcherKind::Wildcard,
                pattern: "*.example.com".into(),
                category: "custom".into(),
            },
            RuleInput {
                id: "ip:block".into(),
                action: Action::Block,
                priority: 50,
                kind: MatcherKind::Ip,
                pattern: "203.0.113.7".into(),
                category: "malware".into(),
            },
        ];
        let config = build_policy_config(
            &[SafeSearchMapping {
                domain: "www.google.com".into(),
                target: "forcesafesearch.google.com".into(),
            }],
            &policy,
            true,
            "cleanweb",
            "secret",
            "utun233",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();
        let rules = value["routing"]["rules"].as_array().unwrap();
        let block = rules
            .iter()
            .find(|rule| {
                rule["domain"].as_array().is_some_and(|domains| {
                    domains.contains(&Value::String("domain:baidu.com".into()))
                })
            })
            .unwrap();
        assert_eq!(block["outboundTag"], "blocked");
        assert!(rules.iter().any(|rule| {
            rule["ip"]
                .as_array()
                .is_some_and(|ips| ips.contains(&Value::String("203.0.113.7/32".into())))
                && rule["outboundTag"] == "blocked"
        }));
        let safe_index = rules
            .iter()
            .position(|rule| rule["outboundTag"] == "safe-via-mihomo")
            .unwrap();
        let block_index = rules.iter().position(|rule| rule == block).unwrap();
        assert!(block_index < safe_index);
    }

    #[test]
    fn generated_config_parses_in_the_pinned_xray_core_when_available() {
        let Ok(binary) = std::env::var("CLEANWEB_TEST_XRAY_BINARY") else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let generated = build_policy_config(
            &[SafeSearchMapping {
                domain: "www.google.com".into(),
                target: "forcesafesearch.google.com".into(),
            }],
            &[RuleInput {
                id: "schema-regex".into(),
                action: Action::Block,
                priority: 30,
                kind: MatcherKind::Regex,
                pattern: "(^|\\.)bad[0-9]+\\.example$".into(),
                category: "test".into(),
            }],
            true,
            "cleanweb",
            "secret",
            "utun233",
        )
        .unwrap();
        let mut config: Value = serde_json::from_str(&generated).unwrap();
        config["log"]["access"] =
            Value::String(directory.path().join("access.log").display().to_string());
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let output = Command::new(binary)
            .args(["run", "-test", "-config"])
            .arg(path)
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Xray's `-test` mode still attempts to create the configured TUN on
        // macOS. A non-root unit test therefore reaches the privilege boundary
        // after parsing; every configuration/schema error fails before it.
        assert!(
            output.status.success() || combined.contains("operation not permitted"),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
