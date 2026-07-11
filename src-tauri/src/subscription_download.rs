use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::header::CONTENT_LENGTH;
use rusqlite::params;
use serde::Serialize;
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
        .user_agent("CleanWeb/0.1")
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

fn parse_proxy_payload(text: &str) -> Result<(RefreshReport, String), String> {
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
            return Ok((
                RefreshReport {
                    detected_format: "clash".into(),
                    imported_count: 0,
                    ignored_count: 0,
                    proxy_count: proxies,
                    group_count: groups,
                },
                payload,
            ));
        }
    }
    let decoded = STANDARD
        .decode(text.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
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
    let count = decoded
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
    Ok((
        RefreshReport {
            detected_format: "uri-list".into(),
            imported_count: 0,
            ignored_count: 0,
            proxy_count: count,
            group_count: 0,
        },
        decoded,
    ))
}

fn detect_rule_format(text: &str) -> SubscriptionFormat {
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
    fn counts_proxy_uri_lists() {
        let (report, payload) = parse_proxy_payload("ss://abc\nvless://def\ninvalid").unwrap();
        assert_eq!(report.proxy_count, 2);
        assert!(payload.contains("vless://"));
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
}
