use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    net::IpAddr,
};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::{
    mihomo::{controller_secret, enabled_policy_rules},
    platform,
    rules::RuleSet,
    storage::AppState,
};

const CONTROLLER_CONNECTIONS: &str = "http://127.0.0.1:19090/connections";
const MAX_LOG_LINES_PER_SYNC: usize = 2_000;
const MAX_LOG_BYTES_PER_SYNC: u64 = 512 * 1024;

#[derive(Debug, Deserialize)]
struct ConnectionsResponse {
    #[serde(default)]
    connections: Vec<Connection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    #[serde(default)]
    metadata: Metadata,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    #[serde(default)]
    host: String,
    #[serde(default)]
    destination_ip: String,
    #[serde(default)]
    destination_port: String,
    #[serde(default)]
    process: String,
    #[serde(default)]
    process_path: String,
}

#[derive(Debug, PartialEq, Eq)]
struct LogDecision {
    observed_at: String,
    domain: Option<String>,
    target_ip: Option<String>,
    target_port: Option<i64>,
    source_ip: Option<String>,
    decision: String,
    rule: String,
    rule_payload: String,
    route: String,
    proxy_group: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLog {
    pub id: String,
    pub observed_at: String,
    pub domain: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: Option<i64>,
    pub decision: String,
    pub rule: Option<String>,
    pub category: Option<String>,
    pub process_name: Option<String>,
    pub operating_system: String,
    pub system_user: String,
    pub source_ip: Option<String>,
    pub route: Option<String>,
    pub proxy_group: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn sync_access_logs(state: State<'_, AppState>) -> Result<usize, String> {
    sync_access_logs_inner(&state).await
}

pub(crate) async fn sync_access_logs_inner(state: &AppState) -> Result<usize, String> {
    if !setting_bool(state, "access_logging_enabled")? {
        return Ok(0);
    }
    let secret = controller_secret(state)?;
    let connections = match reqwest::Client::new()
        .get(CONTROLLER_CONNECTIONS)
        .bearer_auth(secret)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .json::<ConnectionsResponse>()
            .await
            .map(|value| value.connections)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let lines = read_new_log_lines(state)?;
    if lines.is_empty() {
        return Ok(0);
    }
    let os = platform::os_version();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let categories = rule_categories(state)?;
    let policy = RuleSet::compile(enabled_policy_rules(state)?)
        .map_err(|value| format!("日志规则加载失败：{value}"))?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut inserted = 0;
    for line in lines {
        let Some(mut event) = parse_mihomo_log_line(&line).or_else(|| parse_xray_log_line(&line))
        else {
            continue;
        };
        let live = connections
            .iter()
            .find(|connection| connection_matches_event(connection, &event));
        let target_ip = event.target_ip.clone().or_else(|| {
            live.and_then(|connection| {
                (!connection.metadata.destination_ip.is_empty())
                    .then(|| connection.metadata.destination_ip.clone())
            })
        });
        let process = live
            .map(|connection| connection.metadata.process.as_str())
            .unwrap_or_default();
        let process_path = live
            .map(|connection| connection.metadata.process_path.as_str())
            .unwrap_or_default();
        let target_ip_value = target_ip
            .as_deref()
            .and_then(|value| value.parse::<IpAddr>().ok());
        let policy_decision = policy.decide(event.domain.as_deref(), target_ip_value);
        let category = policy_decision
            .as_ref()
            .map(|decision| decision.category.to_owned())
            .or_else(|| categories.get(&event.rule_payload).cloned());
        if let Some(decision) = policy_decision {
            event.rule = decision.rule_id.to_owned();
        }
        let connection_id = format!("event:{:x}", Sha256::digest(line.as_bytes()));
        inserted += db.execute(
            "INSERT OR IGNORE INTO access_logs(connection_id,observed_at,domain,target_ip,target_port,decision,rule,category,process_name,process_path,operating_system,system_user,source_ip,route,proxy_group) VALUES(?1,?2,NULLIF(?3,''),NULLIF(?4,''),?5,?6,NULLIF(?7,''),?8,NULLIF(?9,''),NULLIF(?10,''),?11,?12,NULLIF(?13,''),?14,?15)",
            params![connection_id,event.observed_at,event.domain,target_ip,event.target_port,event.decision,event.rule,category,process,process_path,os,user,event.source_ip,event.route,event.proxy_group]
        ).map_err(error)?;
    }
    cleanup_retention(&db)?;
    Ok(inserted)
}

/// Existing core log files may contain months of traffic while the SQLite
/// access log already contains the same events. A process-local cursor must
/// therefore start at EOF instead of replaying the entire file on every UI
/// launch. Events appended after this snapshot are consumed normally.
pub(crate) fn initialize_log_cursors(state: &AppState) {
    initialize_cursor_to_end(
        &platform::mihomo_log_path(&state.data_dir),
        &state.access_log_cursor,
    );
    initialize_cursor_to_end(
        &platform::xray_access_log_path(&state.data_dir),
        &state.xray_access_log_cursor,
    );
}

fn initialize_cursor_to_end(path: &std::path::Path, cursor: &std::sync::Mutex<u64>) {
    let Ok(length) = path.metadata().map(|metadata| metadata.len()) else {
        return;
    };
    if let Ok(mut cursor) = cursor.lock() {
        *cursor = length;
    }
}

fn read_new_log_lines(state: &AppState) -> Result<Vec<String>, String> {
    let mut lines = read_new_lines(
        &platform::mihomo_log_path(&state.data_dir),
        &state.access_log_cursor,
    )?;
    lines.extend(read_new_lines(
        &platform::xray_access_log_path(&state.data_dir),
        &state.xray_access_log_cursor,
    )?);
    Ok(lines)
}

fn read_new_lines(
    path: &std::path::Path,
    cursor: &std::sync::Mutex<u64>,
) -> Result<Vec<String>, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(value) => return Err(error(value)),
    };
    let length = file.metadata().map_err(error)?.len();
    let mut cursor = cursor.lock().map_err(|_| "日志游标不可用")?;
    if length < *cursor {
        *cursor = 0;
    }
    file.seek(SeekFrom::Start(*cursor)).map_err(error)?;
    let mut reader = BufReader::new(file);
    let mut consumed = 0_u64;
    let mut lines = Vec::new();
    while lines.len() < MAX_LOG_LINES_PER_SYNC && consumed < MAX_LOG_BYTES_PER_SYNC {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).map_err(error)?;
        if bytes == 0 {
            break;
        }
        // Keep an incomplete final line for the next pass. Core processes can
        // still be writing it while CleanWeb reads the file.
        if !line.ends_with('\n') {
            break;
        }
        consumed += bytes as u64;
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
        lines.push(line);
    }
    *cursor += consumed;
    Ok(lines)
}

fn parse_xray_log_line(line: &str) -> Option<LogDecision> {
    // Xray access format:
    // 2026/07/18 10:51:11 from 169.254.10.1:50000 accepted
    // tcp:www.baidu.com:443 [cleanweb-tun -> blocked]
    let (observed_at, remainder) = line.split_once(" from ")?;
    let (source, remainder) = remainder.split_once(" accepted ")?;
    let (destination, route) = remainder.split_once(" [")?;
    let destination = destination
        .strip_prefix("tcp:")
        .or_else(|| destination.strip_prefix("udp:"))?;
    let (destination_host, target_port) = split_endpoint(destination);
    let (domain, target_ip) = if destination_host.parse::<IpAddr>().is_ok() {
        (None, Some(destination_host.to_owned()))
    } else {
        (Some(destination_host.to_ascii_lowercase()), None)
    };
    let route = route
        .split_once(']')
        .map_or(route, |(value, _)| value)
        .trim();
    let outbound = route.rsplit_once(" -> ").map_or(route, |(_, value)| value);
    let blocked = outbound == "blocked";
    let (source_host, _) = split_endpoint(source);
    Some(LogDecision {
        observed_at: observed_at.replace('/', "-").replace(' ', "T"),
        domain,
        target_ip,
        target_port,
        source_ip: (!source_host.is_empty()).then(|| source_host.to_owned()),
        decision: if blocked { "block" } else { "allow" }.into(),
        rule: format!("xray:{outbound}"),
        rule_payload: String::new(),
        route: if blocked {
            "reject"
        } else if outbound == "direct" {
            "direct"
        } else {
            "proxy"
        }
        .into(),
        proxy_group: matches!(outbound, "mihomo" | "safe-via-mihomo").then(|| "CleanWeb".into()),
    })
}

fn parse_mihomo_log_line(line: &str) -> Option<LogDecision> {
    let observed_at = between(line, "time=\"", "\"")?.to_owned();
    let message = line.split_once("msg=\"")?.1;
    let message = message.strip_prefix('[')?;
    let (_, message) = message.split_once("] ")?;
    let (source, remainder) = message.split_once(" --> ")?;
    let (destination, remainder) = remainder.split_once(" match ")?;
    let (rule, route) = remainder.split_once(" using ")?;
    let route = route
        .split(" error:")
        .next()
        .unwrap_or(route)
        .trim_end_matches(['"', '\\'])
        .trim()
        .to_owned();
    let (source_host, _) = split_endpoint(source);
    let (destination_host, target_port) = split_endpoint(destination);
    let (domain, target_ip) = if destination_host.parse::<IpAddr>().is_ok() {
        (None, Some(destination_host.to_owned()))
    } else {
        (Some(destination_host.to_ascii_lowercase()), None)
    };
    let decision = if route.eq_ignore_ascii_case("REJECT") {
        "block"
    } else if domain.is_none() {
        "warning"
    } else {
        "allow"
    };
    let (rule_name, rule_payload) = split_rule(rule);
    let proxy_group = (!route.eq_ignore_ascii_case("DIRECT")
        && !route.eq_ignore_ascii_case("REJECT"))
    .then(|| route.split('[').next().unwrap_or(&route).to_owned());
    Some(LogDecision {
        observed_at,
        domain,
        target_ip,
        target_port,
        source_ip: (!source_host.is_empty()).then(|| source_host.to_owned()),
        decision: decision.into(),
        rule: rule_name,
        rule_payload,
        route: if route.eq_ignore_ascii_case("DIRECT") {
            "direct".into()
        } else if route.eq_ignore_ascii_case("REJECT") {
            "reject".into()
        } else {
            "proxy".into()
        },
        proxy_group,
    })
}

fn connection_matches_event(connection: &Connection, event: &LogDecision) -> bool {
    let host_matches = event
        .domain
        .as_ref()
        .is_some_and(|domain| connection.metadata.host.eq_ignore_ascii_case(domain))
        || event
            .target_ip
            .as_ref()
            .is_some_and(|ip| connection.metadata.destination_ip == *ip);
    host_matches
        && event.target_port.is_none_or(|port| {
            connection.metadata.destination_port.parse::<i64>().ok() == Some(port)
        })
}

fn between<'a>(value: &'a str, start: &str, end: &str) -> Option<&'a str> {
    value
        .split_once(start)?
        .1
        .split_once(end)
        .map(|pair| pair.0)
}

fn split_endpoint(value: &str) -> (&str, Option<i64>) {
    if let Some(value) = value.strip_prefix('[') {
        if let Some((host, port)) = value.rsplit_once("]:") {
            return (host, port.parse().ok());
        }
    }
    value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, port.parse().ok()))
}

fn split_rule(value: &str) -> (String, String) {
    if let Some((name, payload)) = value.split_once('(') {
        return (
            name.to_owned(),
            payload.trim_end_matches(')').trim().to_owned(),
        );
    }
    (value.to_owned(), String::new())
}

#[tauri::command]
pub fn list_access_logs(
    session_token: String,
    decision: Option<String>,
    search: Option<String>,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<AccessLog>, String> {
    state.require_session(&session_token)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let search = search.unwrap_or_default();
    let pattern = format!("%{search}%");
    let mut statement=db.prepare("SELECT connection_id,observed_at,domain,target_ip,target_port,decision,rule,category,process_name,operating_system,system_user,source_ip,route,proxy_group,error FROM access_logs WHERE (?1 IS NULL OR decision=?1) AND (?2='' OR COALESCE(domain,'') LIKE ?3 OR COALESCE(target_ip,'') LIKE ?3 OR COALESCE(process_name,'') LIKE ?3) ORDER BY observed_at DESC LIMIT ?4").map_err(error)?;
    let rows = statement
        .query_map(
            params![decision, search, pattern, limit.unwrap_or(500).min(5000)],
            |row| {
                Ok(AccessLog {
                    id: row.get(0)?,
                    observed_at: row.get(1)?,
                    domain: row.get(2)?,
                    target_ip: row.get(3)?,
                    target_port: row.get(4)?,
                    decision: row.get(5)?,
                    rule: row.get(6)?,
                    category: row.get(7)?,
                    process_name: row.get(8)?,
                    operating_system: row.get(9)?,
                    system_user: row.get(10)?,
                    source_ip: row.get(11)?,
                    route: row.get(12)?,
                    proxy_group: row.get(13)?,
                    error: row.get(14)?,
                })
            },
        )
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows)
}

#[tauri::command]
pub fn clear_access_logs(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    state.require_session(&session_token)?;
    state
        .db
        .lock()
        .map_err(|_| "数据库不可用")?
        .execute("DELETE FROM access_logs", [])
        .map_err(error)
}

#[tauri::command]
pub fn export_access_logs_csv(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    state.require_session(&session_token)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut statement=db.prepare("SELECT observed_at,domain,target_ip,CAST(target_port AS TEXT),decision,rule,category,process_name,operating_system,system_user,source_ip,route,proxy_group,error FROM access_logs ORDER BY observed_at DESC").map_err(error)?;
    let mut output=String::from("time,domain,target_ip,target_port,decision,rule,category,process,os,user,source_ip,route,proxy_group,error\n");
    let rows = statement
        .query_map([], |row| {
            let values = (0..14)
                .map(|index| {
                    row.get::<_, Option<String>>(index)
                        .ok()
                        .flatten()
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            Ok(values)
        })
        .map_err(error)?;
    for row in rows {
        output.push_str(
            &row.map_err(error)?
                .into_iter()
                .map(csv)
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push('\n');
    }
    Ok(output)
}

fn cleanup_retention(db: &rusqlite::Connection) -> Result<(), String> {
    let retention: String = db
        .query_row(
            "SELECT value FROM settings WHERE key='log_retention'",
            [],
            |row| row.get(0),
        )
        .map_err(error)?;
    let days = match retention.as_str() {
        "7d" => Some(7),
        "30d" => Some(30),
        "90d" => Some(90),
        _ => None,
    };
    if let Some(days) = days {
        db.execute(
            "DELETE FROM access_logs WHERE datetime(observed_at) < datetime('now', ?1)",
            params![format!("-{days} days")],
        )
        .map_err(error)?;
    }
    Ok(())
}
fn setting_bool(state: &AppState, key: &str) -> Result<bool, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    Ok(db
        .query_row(
            "SELECT value FROM settings WHERE key=?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .map_err(error)?
        == "true")
}
fn rule_categories(state: &AppState) -> Result<HashMap<String, String>, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut statement = db
        .prepare("SELECT DISTINCT pattern,category FROM imported_rules")
        .map_err(error)?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(error)?;
    let mut categories: HashMap<String, String> = rows;
    let mut statement = db
        .prepare("SELECT pattern,category FROM parent_rules WHERE enabled=1")
        .map_err(error)?;
    for row in statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(error)?
    {
        let (pattern, category) = row.map_err(error)?;
        categories.insert(pattern, category);
    }
    Ok(categories)
}
fn csv(value: String) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::AppState;
    use std::io::Write;

    #[test]
    fn startup_cursor_skips_a_large_existing_core_log() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray-access.log");
        std::fs::write(&path, "old event\n".repeat(100_000)).unwrap();
        let cursor = std::sync::Mutex::new(0);

        initialize_cursor_to_end(&path, &cursor);
        assert_eq!(*cursor.lock().unwrap(), path.metadata().unwrap().len());
        assert!(read_new_lines(&path, &cursor).unwrap().is_empty());

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "new event").unwrap();
        assert_eq!(read_new_lines(&path, &cursor).unwrap(), ["new event"]);
    }

    #[test]
    fn incremental_reader_caps_each_sync_without_losing_lines() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("core.log");
        let total = MAX_LOG_LINES_PER_SYNC + 7;
        let text = (0..total)
            .map(|index| format!("event-{index}\n"))
            .collect::<String>();
        std::fs::write(&path, text).unwrap();
        let cursor = std::sync::Mutex::new(0);

        let first = read_new_lines(&path, &cursor).unwrap();
        let second = read_new_lines(&path, &cursor).unwrap();
        assert_eq!(first.len(), MAX_LOG_LINES_PER_SYNC);
        assert_eq!(second.len(), 7);
        assert_eq!(second.last().map(String::as_str), Some("event-2006"));
        assert_eq!(*cursor.lock().unwrap(), path.metadata().unwrap().len());
    }

    #[test]
    fn retention_cleanup_removes_old_rows() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO access_logs(connection_id,observed_at,decision,operating_system,system_user) VALUES('old','2000-01-01T00:00:00Z','allow','macOS','u')",[]).unwrap();
        cleanup_retention(&db).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn csv_escapes_quotes() {
        assert_eq!(csv("a\"b".into()), "\"a\"\"b\"");
    }

    #[test]
    fn parses_rejected_domain_log_events() {
        let line = r#"time="2026-07-18T10:51:11.609924000+08:00" level=info msg="[TCP] 198.18.0.1:53494 --> www.baidu.com:443 match DomainSuffix(baidu.com) using REJECT""#;
        let event = parse_mihomo_log_line(line).unwrap();
        assert_eq!(event.observed_at, "2026-07-18T10:51:11.609924000+08:00");
        assert_eq!(event.domain.as_deref(), Some("www.baidu.com"));
        assert_eq!(event.target_port, Some(443));
        assert_eq!(event.decision, "block");
        assert_eq!(event.rule, "DomainSuffix");
        assert_eq!(event.rule_payload, "baidu.com");
        assert_eq!(event.route, "reject");
        assert_eq!(event.proxy_group, None);
    }

    #[test]
    fn parses_unknown_ip_and_hides_proxy_node_name() {
        let line = r#"time="2026-07-18T10:51:11+08:00" level=info msg="[TCP] 198.18.0.1:50000 --> 203.0.113.7:443 match Match using CleanWeb[private-node-name]""#;
        let event = parse_mihomo_log_line(line).unwrap();
        assert_eq!(event.domain, None);
        assert_eq!(event.target_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(event.decision, "warning");
        assert_eq!(event.route, "proxy");
        assert_eq!(event.proxy_group.as_deref(), Some("CleanWeb"));
    }

    #[test]
    fn parses_xray_blackhole_access_events() {
        let line = "2026/07/18 10:51:11 from 169.254.10.1:50000 accepted tcp:www.baidu.com:443 [cleanweb-tun -> blocked] email: test";
        let event = parse_xray_log_line(line).unwrap();
        assert_eq!(event.observed_at, "2026-07-18T10:51:11");
        assert_eq!(event.domain.as_deref(), Some("www.baidu.com"));
        assert_eq!(event.target_port, Some(443));
        assert_eq!(event.decision, "block");
        assert_eq!(event.route, "reject");
        assert_eq!(event.proxy_group, None);
    }

    #[test]
    fn parent_rule_category_overrides_subscription_category_for_logs() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO subscriptions(id,kind,name,url) VALUES('s','rule','s','https://example.test')", []).unwrap();
        db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('s','1','Suffix','example.com','Block','ads',1)", []).unwrap();
        db.execute("INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('p','block','Suffix','example.com','custom')", []).unwrap();
        drop(db);

        assert_eq!(
            rule_categories(&state)
                .unwrap()
                .get("example.com")
                .map(String::as_str),
            Some("custom")
        );
    }
}
