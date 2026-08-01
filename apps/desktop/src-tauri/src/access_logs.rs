use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::{mihomo::controller_secret, platform, storage::AppState};

const CONTROLLER_CONNECTIONS: &str = "http://127.0.0.1:19090/connections";
const CONTROLLER_LOGS: &str = "http://127.0.0.1:19090/logs";
const ACCESS_LOGS_UPDATED_EVENT: &str = "access-logs-updated";
const LOG_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(5);
const LOG_FILE_SYNC_INTERVAL: Duration = Duration::from_secs(5);
const LOG_SYNC_OFFSET_PREFIX: &str = "access_log_file_offset:";
const HIGH_FREQUENCY_LOG_BUCKET_MS: i64 = 10_000;
const UTF8_BOM: &str = "\u{feff}";
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_LOG: &str = "/Library/Application Support/CleanWeb/mihomo.log";

#[derive(Debug, Deserialize)]
struct ConnectionsResponse {
    #[serde(default)]
    connections: Vec<Connection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    id: String,
    #[serde(default)]
    start: String,
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    rule: String,
    #[serde(default)]
    rule_payload: String,
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
    source_ip: String,
    #[serde(default)]
    process: String,
    #[serde(default)]
    process_path: String,
}

#[derive(Debug, Deserialize)]
struct LogLine {
    payload: Option<String>,
}

struct ParsedLogEvent {
    id: String,
    observed_at: Option<String>,
    domain: Option<String>,
    target_ip: Option<String>,
    port: Option<i64>,
    decision: &'static str,
    rule: Option<String>,
    category: Option<&'static str>,
    process_name: Option<String>,
    route: String,
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
    pub repeat_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogStats {
    pub block: i64,
    pub allow: i64,
    pub warning: i64,
    pub total: i64,
    pub today_block: i64,
    pub today_allow: i64,
    pub today_warning: i64,
    pub today_total: i64,
}

pub fn start_access_log_collector(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .read_timeout(LOG_STREAM_READ_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        loop {
            let state = app.state::<AppState>();
            if !setting_bool(&state, "access_logging_enabled").unwrap_or(false) {
                tokio_sleep(Duration::from_secs(30)).await;
                continue;
            }
            let secret = match controller_secret(&state) {
                Ok(value) => value,
                Err(_) => {
                    sync_mihomo_log_files_and_emit(&app, &state);
                    tokio_sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let mut response = match client
                .get(CONTROLLER_LOGS)
                .query(&[("level", "info")])
                .bearer_auth(secret)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => response,
                _ => {
                    sync_mihomo_log_files_and_emit(&app, &state);
                    tokio_sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let _ = mark_mihomo_log_files_synced_to_end(&state);
            let mut buffer = String::new();
            let mut last_file_sync = Instant::now();
            while let Ok(Some(chunk)) = response.chunk().await {
                buffer.push_str(&String::from_utf8_lossy(&chunk));
                while let Some(index) = buffer.find('\n') {
                    let line = buffer[..index].trim().to_owned();
                    buffer.drain(..=index);
                    if line.is_empty() {
                        continue;
                    }
                    let state = app.state::<AppState>();
                    if insert_mihomo_log_line(&state, &line).unwrap_or(0) > 0 {
                        let _ = app.emit(ACCESS_LOGS_UPDATED_EVENT, ());
                    }
                }
                if last_file_sync.elapsed() >= LOG_FILE_SYNC_INTERVAL {
                    let state = app.state::<AppState>();
                    sync_mihomo_log_files_and_emit(&app, &state);
                    last_file_sync = Instant::now();
                }
            }
            let state = app.state::<AppState>();
            sync_mihomo_log_files_and_emit(&app, &state);
            tokio_sleep(Duration::from_secs(2)).await;
        }
    });
}

fn sync_mihomo_log_files_and_emit(app: &AppHandle, state: &AppState) {
    if sync_mihomo_log_files(state).unwrap_or(0) > 0 {
        let _ = app.emit(ACCESS_LOGS_UPDATED_EVENT, ());
    }
}

#[tauri::command]
pub async fn sync_access_logs(state: State<'_, AppState>) -> Result<usize, String> {
    sync_access_logs_inner(&state).await
}

pub(crate) async fn sync_access_logs_inner(state: &AppState) -> Result<usize, String> {
    if !setting_bool(state, "access_logging_enabled")? {
        return Ok(0);
    }
    let mut inserted = sync_mihomo_log_files(state)?;
    let secret = controller_secret(state)?;
    let response = match reqwest::Client::new()
        .get(CONTROLLER_CONNECTIONS)
        .bearer_auth(secret)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .json::<ConnectionsResponse>()
            .await
            .map_err(error)?,
        _ => return Ok(inserted),
    };
    let os = platform::os_version();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let categories = rule_categories(state)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    for connection in response.connections {
        let route = if connection.chains.is_empty() {
            None
        } else {
            Some(connection.chains.join(" → "))
        };
        let rejected = connection
            .chains
            .iter()
            .any(|item| item.eq_ignore_ascii_case("REJECT"));
        let dns_resolution = is_dns_resolution_connection(&connection);
        let decision = if rejected {
            "block"
        } else if dns_resolution {
            "allow"
        } else if connection.metadata.host.is_empty() {
            "warning"
        } else {
            "allow"
        };
        let category = if dns_resolution {
            Some("DNS 解析".to_owned())
        } else {
            categories.get(&connection.rule_payload).cloned()
        };
        let rule_id = intern_access_log_string(&db, Some(connection.rule.as_str()))?;
        let category_id = intern_access_log_string(&db, category.as_deref())?;
        let process_name_id =
            intern_access_log_string(&db, Some(connection.metadata.process.as_str()))?;
        let process_path_id =
            intern_access_log_string(&db, Some(connection.metadata.process_path.as_str()))?;
        let operating_system_id = intern_access_log_string(&db, Some(os.as_str()))?;
        let system_user_id = intern_access_log_string(&db, Some(user.as_str()))?;
        let source_ip_id =
            intern_access_log_string(&db, Some(connection.metadata.source_ip.as_str()))?;
        let route_id = intern_access_log_string(&db, route.as_deref())?;
        let proxy_group_id =
            intern_access_log_string(&db, connection.chains.first().map(String::as_str))?;
        let domain_id = intern_access_log_string(&db, Some(connection.metadata.host.as_str()))?;
        let target_ip_id =
            intern_access_log_string(&db, Some(connection.metadata.destination_ip.as_str()))?;
        inserted += db.execute(
            "INSERT OR IGNORE INTO access_logs(connection_hash,observed_at_ms,domain_string_id,target_ip_string_id,target_port,decision_code,rule_string_id,category_string_id,process_name_string_id,process_path_string_id,operating_system_string_id,system_user_string_id,source_ip_string_id,route_string_id,proxy_group_string_id) VALUES(?1,CAST(COALESCE((julianday(?2)-2440587.5)*86400000,(julianday('now')-2440587.5)*86400000) AS INTEGER),?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![connection_hash(&connection.id),connection.start,domain_id,target_ip_id,connection.metadata.destination_port.parse::<i64>().ok(),decision_code(decision),rule_id,category_id,process_name_id,process_path_id,operating_system_id,system_user_id,source_ip_id,route_id,proxy_group_id]
        ).map_err(error)?;
    }
    cleanup_retention(&db)?;
    Ok(inserted)
}

fn insert_mihomo_log_line(state: &AppState, line: &str) -> Result<usize, String> {
    insert_mihomo_log_line_inner(state, line, true)
}

fn insert_mihomo_log_line_inner(
    state: &AppState,
    line: &str,
    cleanup: bool,
) -> Result<usize, String> {
    let Some(event) = parse_mihomo_log_event(line) else {
        return Ok(0);
    };
    let observed_at = event
        .observed_at
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| current_timestamp(state));
    let os = platform::os_version();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let inserted = insert_parsed_log_event(&db, &event, &observed_at, &os, &user)?;
    if cleanup {
        cleanup_retention(&db)?;
    }
    Ok(inserted)
}

fn parse_mihomo_log_event(line: &str) -> Option<ParsedLogEvent> {
    let message = log_message(line);
    let route = log_route(&message)?;
    let (target, port) = log_target(&message)?;
    let rule = log_rule(&message);
    let decision = if route.eq_ignore_ascii_case("REJECT") {
        "block"
    } else {
        "allow"
    };
    let (domain, target_ip) = split_domain_and_ip(target);
    let dns_resolution = decision == "allow" && port == Some(53);
    Some(ParsedLogEvent {
        id: format!("mihomo-log-{}", line_id_suffix(line)),
        observed_at: log_time(line),
        domain,
        target_ip,
        port,
        decision,
        rule,
        category: dns_resolution.then_some("DNS 解析"),
        process_name: dns_resolution.then(|| "mihomo".to_owned()),
        route,
    })
}

fn insert_parsed_log_event(
    db: &rusqlite::Connection,
    event: &ParsedLogEvent,
    observed_at: &str,
    os: &str,
    user: &str,
) -> Result<usize, String> {
    let domain_id = intern_access_log_string(db, event.domain.as_deref())?;
    let target_ip_id = intern_access_log_string(db, event.target_ip.as_deref())?;
    let rule_id = intern_access_log_string(db, event.rule.as_deref())?;
    let category_id = intern_access_log_string(db, event.category)?;
    let process_name_id = intern_access_log_string(db, event.process_name.as_deref())?;
    let os_id = intern_access_log_string(db, Some(os))?;
    let user_id = intern_access_log_string(db, Some(user))?;
    let route_id = intern_access_log_string(db, Some(event.route.as_str()))?;
    let observed_at_ms = observed_at_ms(db, observed_at)?;
    let event_hash = connection_hash(&event.id);
    if should_rollup_event(event) {
        if db
            .query_row(
                "SELECT 1 FROM access_logs WHERE connection_hash=?1",
                params![event_hash.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(error)?
            .is_some()
        {
            return Ok(0);
        }
        if let Some(updated) = update_recent_rollup_event(
            db,
            event,
            observed_at_ms,
            domain_id,
            target_ip_id,
            rule_id,
            category_id,
            process_name_id,
            os_id,
            user_id,
            route_id,
        )? {
            return Ok(updated);
        }
    }
    db.execute(
        "INSERT OR IGNORE INTO access_logs(connection_hash,observed_at_ms,domain_string_id,target_ip_string_id,target_port,decision_code,rule_string_id,category_string_id,process_name_string_id,operating_system_string_id,system_user_string_id,route_string_id,proxy_group_string_id,repeat_count) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?12,1)",
        params![
            event_hash,
            observed_at_ms,
            domain_id,
            target_ip_id,
            event.port,
            decision_code(event.decision),
            rule_id,
            category_id,
            process_name_id,
            os_id,
            user_id,
            route_id
        ],
    )
    .map_err(error)
}

fn should_rollup_event(event: &ParsedLogEvent) -> bool {
    event.domain.is_some() || event.target_ip.is_some()
}

#[allow(clippy::too_many_arguments)]
fn update_recent_rollup_event(
    db: &rusqlite::Connection,
    event: &ParsedLogEvent,
    observed_at_ms: i64,
    domain_id: Option<i64>,
    target_ip_id: Option<i64>,
    rule_id: Option<i64>,
    category_id: Option<i64>,
    process_name_id: Option<i64>,
    os_id: Option<i64>,
    user_id: Option<i64>,
    route_id: Option<i64>,
) -> Result<Option<usize>, String> {
    let recent_id = db
        .query_row(
            "SELECT id
               FROM access_logs
              WHERE observed_at_ms BETWEEN ?1 AND ?2
                AND COALESCE(domain_string_id,-1)=COALESCE(?3,-1)
                AND COALESCE(target_ip_string_id,-1)=COALESCE(?4,-1)
                AND COALESCE(target_port,-1)=COALESCE(?5,-1)
                AND decision_code=?6
                AND COALESCE(rule_string_id,-1)=COALESCE(?7,-1)
                AND COALESCE(category_string_id,-1)=COALESCE(?8,-1)
                AND COALESCE(process_name_string_id,-1)=COALESCE(?9,-1)
                AND COALESCE(operating_system_string_id,-1)=COALESCE(?10,-1)
                AND COALESCE(system_user_string_id,-1)=COALESCE(?11,-1)
                AND COALESCE(route_string_id,-1)=COALESCE(?12,-1)
              ORDER BY observed_at_ms DESC,id DESC
              LIMIT 1",
            params![
                observed_at_ms - HIGH_FREQUENCY_LOG_BUCKET_MS,
                observed_at_ms,
                domain_id,
                target_ip_id,
                event.port,
                decision_code(event.decision),
                rule_id,
                category_id,
                process_name_id,
                os_id,
                user_id,
                route_id
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(error)?;
    let Some(recent_id) = recent_id else {
        return Ok(None);
    };
    db.execute(
        "UPDATE access_logs
            SET observed_at_ms=?1,
                repeat_count=repeat_count+1
          WHERE id=?2",
        params![observed_at_ms, recent_id],
    )
    .map(Some)
    .map_err(error)
}

fn observed_at_ms(db: &rusqlite::Connection, observed_at: &str) -> Result<i64, String> {
    db.query_row(
        "SELECT CAST(COALESCE((julianday(?1)-2440587.5)*86400000,(julianday('now')-2440587.5)*86400000) AS INTEGER)",
        params![observed_at],
        |row| row.get(0),
    )
    .map_err(error)
}

fn sync_mihomo_log_files(state: &AppState) -> Result<usize, String> {
    let mut inserted = 0;
    for path in mihomo_log_paths(state) {
        inserted += sync_mihomo_log_file(state, &path)?;
    }
    Ok(inserted)
}

fn mark_mihomo_log_files_synced_to_end(state: &AppState) -> Result<(), String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    for path in mihomo_log_paths(state) {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        set_log_file_offset(&db, &log_file_offset_key(&path), metadata.len())?;
    }
    Ok(())
}

fn sync_mihomo_log_file(state: &AppState, path: &Path) -> Result<usize, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(0),
    };
    let file_len = file.metadata().map_err(error)?.len();
    let offset_key = log_file_offset_key(path);
    let start_offset = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        log_file_offset(&db, &offset_key)?.filter(|offset| *offset <= file_len)
    }
    .unwrap_or(0);
    file.seek(SeekFrom::Start(start_offset)).map_err(error)?;
    let events = BufReader::new(&mut file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| parse_mihomo_log_event(&line))
        .collect::<Vec<_>>();
    let end_offset = file.stream_position().map_err(error)?;
    if events.is_empty() && end_offset == start_offset {
        return Ok(0);
    }
    let fallback_timestamp = current_timestamp(state);
    let os = platform::os_version();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut inserted = 0;
    for event in events {
        let observed_at = event.observed_at.as_deref().unwrap_or(&fallback_timestamp);
        inserted += insert_parsed_log_event(&db, &event, observed_at, &os, &user)?;
    }
    if inserted > 0 {
        cleanup_retention(&db)?;
    }
    set_log_file_offset(&db, &offset_key, end_offset)?;
    Ok(inserted)
}

fn log_file_offset_key(path: &Path) -> String {
    format!(
        "{}{:x}",
        LOG_SYNC_OFFSET_PREFIX,
        Sha256::digest(path.display().to_string().as_bytes())
    )
}

fn log_file_offset(db: &rusqlite::Connection, key: &str) -> Result<Option<u64>, String> {
    db.query_row(
        "SELECT value FROM settings WHERE key=?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(error)
    .map(|value| value.and_then(|text| text.parse().ok()))
}

fn set_log_file_offset(db: &rusqlite::Connection, key: &str, offset: u64) -> Result<(), String> {
    db.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, offset.to_string()],
    )
    .map(|_| ())
    .map_err(error)
}

fn mihomo_log_paths(state: &AppState) -> Vec<PathBuf> {
    let paths = vec![state.data_dir.join("mihomo/mihomo.log")];
    #[cfg(target_os = "macos")]
    let mut paths = paths;
    #[cfg(target_os = "macos")]
    paths.push(PathBuf::from(MACOS_PRIVILEGED_LOG));
    paths
}

fn log_message(line: &str) -> String {
    if let Some(message) = logfmt_msg(line) {
        return message;
    }
    serde_json::from_str::<LogLine>(line)
        .ok()
        .and_then(|event| event.payload)
        .unwrap_or_else(|| line.to_owned())
}

fn logfmt_msg(line: &str) -> Option<String> {
    let value = line.split_once(" msg=")?.1.trim();
    if let Some(rest) = value.strip_prefix('"') {
        let end = rest.rfind('"')?;
        return Some(rest[..end].replace("\\\"", "\""));
    }
    Some(value.split_whitespace().next()?.to_owned())
}

fn log_time(line: &str) -> Option<String> {
    let value = line.split_once("time=")?.1.trim();
    let rest = value.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn log_target(message: &str) -> Option<(String, Option<i64>)> {
    let after_arrow = message.split_once("-->")?.1.trim();
    let target = after_arrow.split_whitespace().next()?.trim_matches(',');
    let target = target.trim_start_matches('[').trim_end_matches(']');
    let (host, port) = target.rsplit_once(':').unwrap_or((target, ""));
    let domain = host.trim_matches(['[', ']']).trim().to_owned();
    if domain.is_empty() {
        return None;
    }
    Some((domain, port.parse::<i64>().ok()))
}

fn log_rule(message: &str) -> Option<String> {
    message
        .split_once(" match ")
        .and_then(|(_, value)| value.split_once(" using ").map(|(rule, _)| rule.trim()))
        .filter(|rule| !rule.is_empty())
        .map(str::to_owned)
}

fn log_route(message: &str) -> Option<String> {
    message
        .split_once(" using ")
        .and_then(|(_, value)| value.split_whitespace().next())
        .map(|route| route.trim_matches(',').to_owned())
        .filter(|route| !route.is_empty())
}

fn split_domain_and_ip(target: String) -> (Option<String>, Option<String>) {
    if target.parse::<IpAddr>().is_ok() {
        (None, Some(target))
    } else {
        (Some(target), None)
    }
}

fn is_dns_resolution_connection(connection: &Connection) -> bool {
    connection.metadata.destination_port == "53"
        && !connection
            .chains
            .iter()
            .any(|item| item.eq_ignore_ascii_case("REJECT"))
}

#[cfg(test)]
fn normalize_dns_resolution_rows(db: &rusqlite::Connection) -> Result<(), String> {
    let category_id = intern_access_log_string(db, Some("DNS 解析"))?;
    let process_id = intern_access_log_string(db, Some("mihomo"))?;
    db.execute(
        "UPDATE access_logs
            SET decision_code=0,
                category_string_id=COALESCE(category_string_id,?1),
                process_name_string_id=COALESCE(process_name_string_id,?2)
          WHERE decision_code=2
            AND target_port=53
            AND COALESCE(route_string_id,0)<>(SELECT COALESCE(MAX(id),-1) FROM access_log_strings WHERE value='REJECT')",
        params![category_id, process_id],
    )
    .map(|_| ())
    .map_err(error)
}

fn intern_access_log_string(
    db: &rusqlite::Connection,
    value: Option<&str>,
) -> Result<Option<i64>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    db.execute(
        "INSERT OR IGNORE INTO access_log_strings(value) VALUES(?1)",
        params![value],
    )
    .map_err(error)?;
    db.query_row(
        "SELECT id FROM access_log_strings WHERE value=?1",
        params![value],
        |row| row.get(0),
    )
    .map(Some)
    .map_err(error)
}

fn connection_hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes())[..8].to_vec()
}

fn decision_code(value: &str) -> i64 {
    match value {
        "block" => 1,
        "warning" => 2,
        _ => 0,
    }
}

fn line_id_suffix(line: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(line.as_bytes()))
}

async fn tokio_sleep(duration: Duration) {
    tauri::async_runtime::spawn_blocking(move || std::thread::sleep(duration))
        .await
        .ok();
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
    let mut statement=db.prepare(
        "SELECT CAST(l.id AS TEXT),
                strftime('%Y-%m-%dT%H:%M:%SZ', l.observed_at_ms / 1000, 'unixepoch'),
                domain_s.value,
                target_ip_s.value,
                l.target_port,
                CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                rule_s.value,
                category_s.value,
                process_s.value,
                os_s.value,
                user_s.value,
                source_s.value,
                route_s.value,
                proxy_s.value,
                error_s.value,
                l.repeat_count
           FROM access_logs l
           LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
           LEFT JOIN access_log_strings target_ip_s ON target_ip_s.id=l.target_ip_string_id
           LEFT JOIN access_log_strings rule_s ON rule_s.id=l.rule_string_id
           LEFT JOIN access_log_strings category_s ON category_s.id=l.category_string_id
           LEFT JOIN access_log_strings process_s ON process_s.id=l.process_name_string_id
           LEFT JOIN access_log_strings os_s ON os_s.id=l.operating_system_string_id
           LEFT JOIN access_log_strings user_s ON user_s.id=l.system_user_string_id
           LEFT JOIN access_log_strings source_s ON source_s.id=l.source_ip_string_id
           LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
           LEFT JOIN access_log_strings proxy_s ON proxy_s.id=l.proxy_group_string_id
           LEFT JOIN access_log_strings error_s ON error_s.id=l.error_string_id
          WHERE (?1 IS NULL OR CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END=?1)
            AND (?2='' OR COALESCE(domain_s.value,'') LIKE ?3
                       OR COALESCE(target_ip_s.value,'') LIKE ?3
                       OR COALESCE(rule_s.value,'') LIKE ?3
                       OR COALESCE(category_s.value,'') LIKE ?3
                       OR COALESCE(process_s.value,'') LIKE ?3
                       OR COALESCE(route_s.value,'') LIKE ?3
                       OR COALESCE(proxy_s.value,'') LIKE ?3)
          ORDER BY l.observed_at_ms DESC, l.id DESC LIMIT ?4"
    ).map_err(error)?;
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
                    repeat_count: row.get(15)?,
                })
            },
        )
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows)
}

#[tauri::command]
pub fn access_log_stats(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<AccessLogStats, String> {
    state.require_session(&session_token)?;
    access_log_stats_inner(&state)
}

#[tauri::command]
pub fn public_access_log_stats(state: State<'_, AppState>) -> Result<AccessLogStats, String> {
    access_log_stats_inner(&state)
}

fn access_log_stats_inner(state: &AppState) -> Result<AccessLogStats, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.query_row(
        "SELECT
           COALESCE(SUM(CASE WHEN decision_code=1 THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN decision_code=0 THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN decision_code=2 THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(repeat_count),0),
           COALESCE(SUM(CASE WHEN decision_code=1 AND date(observed_at_ms / 1000,'unixepoch','localtime')=date('now','localtime') THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN decision_code=0 AND date(observed_at_ms / 1000,'unixepoch','localtime')=date('now','localtime') THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN decision_code=2 AND date(observed_at_ms / 1000,'unixepoch','localtime')=date('now','localtime') THEN repeat_count ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN date(observed_at_ms / 1000,'unixepoch','localtime')=date('now','localtime') THEN repeat_count ELSE 0 END),0)
         FROM access_logs",
        [],
        |row| {
            Ok(AccessLogStats {
                block: row.get(0)?,
                allow: row.get(1)?,
                warning: row.get(2)?,
                total: row.get(3)?,
                today_block: row.get(4)?,
                today_allow: row.get(5)?,
                today_warning: row.get(6)?,
                today_total: row.get(7)?,
            })
        },
    )
    .map_err(error)
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
    export_access_logs_csv_inner(&state)
}

#[tauri::command]
pub fn export_access_logs_csv_to_path(
    session_token: String,
    path: PathBuf,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    let csv = export_access_logs_csv_inner(&state)?;
    std::fs::write(path, csv.as_bytes()).map_err(error)
}

fn export_access_logs_csv_inner(state: &AppState) -> Result<String, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut statement = db
        .prepare(
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', l.observed_at_ms / 1000, 'unixepoch'),
                domain_s.value,
                target_ip_s.value,
                CAST(l.target_port AS TEXT),
                CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                rule_s.value,
                category_s.value,
                process_s.value,
                os_s.value,
                user_s.value,
                source_s.value,
                route_s.value,
                proxy_s.value,
                error_s.value,
                CAST(l.repeat_count AS TEXT)
           FROM access_logs l
           LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
           LEFT JOIN access_log_strings target_ip_s ON target_ip_s.id=l.target_ip_string_id
           LEFT JOIN access_log_strings rule_s ON rule_s.id=l.rule_string_id
           LEFT JOIN access_log_strings category_s ON category_s.id=l.category_string_id
           LEFT JOIN access_log_strings process_s ON process_s.id=l.process_name_string_id
           LEFT JOIN access_log_strings os_s ON os_s.id=l.operating_system_string_id
           LEFT JOIN access_log_strings user_s ON user_s.id=l.system_user_string_id
           LEFT JOIN access_log_strings source_s ON source_s.id=l.source_ip_string_id
           LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
           LEFT JOIN access_log_strings proxy_s ON proxy_s.id=l.proxy_group_string_id
           LEFT JOIN access_log_strings error_s ON error_s.id=l.error_string_id
          ORDER BY l.observed_at_ms DESC, l.id DESC",
        )
        .map_err(error)?;
    let mut output = String::from(UTF8_BOM);
    output.push_str("time,domain,target_ip,target_port,decision,rule,category,process,os,user,source_ip,route,proxy_group,error,repeat_count\n");
    let rows = statement
        .query_map([], |row| {
            let values = (0..15)
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
            "DELETE FROM access_logs WHERE observed_at_ms < CAST((julianday('now', ?1)-2440587.5)*86400000 AS INTEGER)",
            params![format!("-{days} days")],
        )
        .map_err(error)?;
    }
    Ok(())
}

fn current_timestamp(state: &AppState) -> String {
    state
        .db
        .lock()
        .ok()
        .and_then(|db| {
            db.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')", [], |row| {
                row.get(0)
            })
            .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
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
    Ok(rows)
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

    fn insert_test_access_log(
        db: &rusqlite::Connection,
        connection_id: &str,
        observed_at: &str,
        decision: &str,
        target_port: Option<i64>,
        route: Option<&str>,
    ) {
        let route_id = intern_access_log_string(db, route).unwrap();
        let os_id = intern_access_log_string(db, Some("macOS")).unwrap();
        let user_id = intern_access_log_string(db, Some("u")).unwrap();
        db.execute(
            "INSERT INTO access_logs(connection_hash,observed_at_ms,target_port,decision_code,operating_system_string_id,system_user_string_id,route_string_id)
             VALUES(?1,CAST(COALESCE((julianday(?2)-2440587.5)*86400000,(julianday('now')-2440587.5)*86400000) AS INTEGER),?3,?4,?5,?6,?7)",
            params![
                connection_hash(connection_id),
                observed_at,
                target_port,
                decision_code(decision),
                os_id,
                user_id,
                route_id
            ],
        )
        .unwrap();
    }

    #[test]
    fn retention_cleanup_removes_old_rows() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        insert_test_access_log(&db, "old", "2000-01-01T00:00:00Z", "allow", None, None);
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
    fn exported_csv_starts_with_utf8_bom_for_spreadsheet_apps() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            let domain_id = intern_access_log_string(&db, Some("搜索.example")).unwrap();
            let category_id = intern_access_log_string(&db, Some("DNS 解析")).unwrap();
            let os_id = intern_access_log_string(&db, Some("macOS")).unwrap();
            let user_id = intern_access_log_string(&db, Some("u")).unwrap();
            db.execute(
                "INSERT INTO access_logs(connection_hash,observed_at_ms,domain_string_id,decision_code,category_string_id,operating_system_string_id,system_user_string_id,repeat_count)
                 VALUES(?1,CAST((julianday('2026-07-20T18:20:19Z')-2440587.5)*86400000 AS INTEGER),?2,1,?3,?4,?5,1)",
                params![
                    connection_hash("csv-bom"),
                    domain_id,
                    category_id,
                    os_id,
                    user_id
                ],
            )
            .unwrap();
        }

        let output = export_access_logs_csv_inner(&state).unwrap();
        assert!(output.starts_with(UTF8_BOM));
        assert!(output.contains("\"搜索.example\""));
        assert!(output.contains("\"DNS 解析\""));
    }

    #[test]
    fn parses_reject_log_target_and_rule() {
        let message =
            "[TCP] 127.0.0.1:54321 --> baidu.com:443 match DomainSuffix(baidu.com) using REJECT";
        assert_eq!(log_target(message), Some(("baidu.com".into(), Some(443))));
        assert_eq!(log_rule(message), Some("DomainSuffix(baidu.com)".into()));
        assert_eq!(log_route(message), Some("REJECT".into()));
    }

    #[test]
    fn extracts_mihomo_logfmt_message() {
        let line = r#"time="2026-07-20T17:21:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:54135 --> www.baidu.com:443 match DomainSuffix(baidu.com) using REJECT""#;
        assert_eq!(
            log_message(line),
            "[TCP] 198.18.0.1:54135 --> www.baidu.com:443 match DomainSuffix(baidu.com) using REJECT"
        );
        assert_eq!(
            log_time(line),
            Some("2026-07-20T17:21:19.379133000+08:00".into())
        );
    }

    #[test]
    fn inserts_reject_log_events_from_json_payloads() {
        let state = AppState::open(":memory:").unwrap();
        let line = r#"{"type":"info","payload":"[TCP] 127.0.0.1:54321 --> baidu.com:443 match DomainSuffix(baidu.com) using REJECT"}"#;
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 1);
        let db = state.db.lock().unwrap();
        let (domain, decision): (String, String) = db
            .query_row(
                "SELECT domain_s.value,CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END
                   FROM access_logs l
                   LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
                  LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(domain, "baidu.com");
        assert_eq!(decision, "block");
    }

    #[test]
    fn inserts_connection_log_events_from_mihomo_logfmt_once() {
        let state = AppState::open(":memory:").unwrap();
        let line = r#"time="2026-07-20T17:21:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:54135 --> www.baidu.com:443 match DomainSuffix(baidu.com) using REJECT""#;
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 1);
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 0);
        let db = state.db.lock().unwrap();
        let (observed_at, domain, decision, route): (String, String, String, String) = db
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', l.observed_at_ms / 1000, 'unixepoch'),
                        domain_s.value,
                        CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                        route_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
                   LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
                  LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(observed_at, "2026-07-20T09:21:19Z");
        assert_eq!(domain, "www.baidu.com");
        assert_eq!(decision, "block");
        assert_eq!(route, "REJECT");
    }

    #[test]
    fn inserts_allowed_log_events_from_mihomo_logfmt() {
        let state = AppState::open(":memory:").unwrap();
        let line = r#"time="2026-07-20T18:20:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:54135 --> example.com:443 match Match() using DIRECT""#;
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 1);
        let db = state.db.lock().unwrap();
        let (domain, decision, route): (String, String, String) = db
            .query_row(
                "SELECT domain_s.value,
                        CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                        route_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
                   LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
                  LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(decision, "allow");
        assert_eq!(route, "DIRECT");
    }

    #[test]
    fn rolls_up_high_frequency_direct_allow_logs() {
        let state = AppState::open(":memory:").unwrap();
        for source_port in [54135, 54136, 54137] {
            let line = format!(
                r#"time="2026-07-20T18:20:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:{source_port} --> datacloak.cpirhzl.com:5600 match IPCIDR(116.224.0.0/12) using DIRECT""#
            );
            assert_eq!(
                insert_mihomo_log_line_inner(&state, &line, false).unwrap(),
                1
            );
        }

        let stats = access_log_stats_inner(&state).unwrap();
        assert_eq!(stats.allow, 3);
        assert_eq!(stats.total, 3);
        let db = state.db.lock().unwrap();
        let (rows, repeat_count): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),MAX(repeat_count) FROM access_logs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(repeat_count, 3);
    }

    #[test]
    fn rolls_up_repeated_reject_logs() {
        let state = AppState::open(":memory:").unwrap();
        for source_port in [54135, 54136] {
            let line = format!(
                r#"time="2026-07-20T18:20:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:{source_port} --> bad.example:443 match DomainSuffix(bad.example) using REJECT""#
            );
            assert_eq!(
                insert_mihomo_log_line_inner(&state, &line, false).unwrap(),
                1
            );
        }

        let db = state.db.lock().unwrap();
        let (rows, repeat_count): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),MAX(repeat_count) FROM access_logs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(repeat_count, 2);
    }

    #[test]
    fn rolls_up_repeated_dns_logs() {
        let state = AppState::open(":memory:").unwrap();
        for source_port in [54135, 54136, 54137] {
            let line = format!(
                r#"time="2026-07-20T18:20:19.379133000+08:00" level=info msg="[UDP] 198.18.0.1:{source_port} --> 119.29.29.29:53 match Match() using DIRECT""#
            );
            assert_eq!(
                insert_mihomo_log_line_inner(&state, &line, false).unwrap(),
                1
            );
        }

        let stats = access_log_stats_inner(&state).unwrap();
        assert_eq!(stats.allow, 3);
        assert_eq!(stats.total, 3);
        let db = state.db.lock().unwrap();
        let (rows, repeat_count, category): (i64, i64, String) = db
            .query_row(
                "SELECT COUNT(*),MAX(l.repeat_count),category_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings category_s ON category_s.id=l.category_string_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(repeat_count, 3);
        assert_eq!(category, "DNS 解析");
    }

    #[test]
    fn starts_new_rollup_when_repeated_logs_are_not_continuous() {
        let state = AppState::open(":memory:").unwrap();
        for (source_port, time) in [
            (54135, "2026-07-20T18:20:19.379133000+08:00"),
            (54136, "2026-07-20T18:20:25.379133000+08:00"),
            (54137, "2026-07-20T18:20:40.379133000+08:00"),
        ] {
            let line = format!(
                r#"time="{time}" level=info msg="[TCP] 198.18.0.1:{source_port} --> repeated.example:443 match Match() using DIRECT""#
            );
            assert_eq!(
                insert_mihomo_log_line_inner(&state, &line, false).unwrap(),
                1
            );
        }

        let stats = access_log_stats_inner(&state).unwrap();
        assert_eq!(stats.allow, 3);
        assert_eq!(stats.total, 3);
        let db = state.db.lock().unwrap();
        let (rows, max_repeat_count): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),MAX(repeat_count) FROM access_logs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(max_repeat_count, 2);
    }

    #[test]
    fn syncs_mihomo_log_files_incrementally() {
        let state = AppState::open(":memory:").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mihomo.log");
        std::fs::write(
            &path,
            r#"time="2026-07-20T18:20:19.379133000+08:00" level=info msg="[TCP] 198.18.0.1:54135 --> example.com:443 match Match() using DIRECT"
"#,
        )
        .unwrap();

        assert_eq!(sync_mihomo_log_file(&state, &path).unwrap(), 1);
        assert_eq!(sync_mihomo_log_file(&state, &path).unwrap(), 0);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(
                br#"time="2026-07-20T18:20:20.379133000+08:00" level=info msg="[TCP] 198.18.0.1:54136 --> other.example:443 match Match() using DIRECT"
"#,
            )
            .unwrap();
        assert_eq!(sync_mihomo_log_file(&state, &path).unwrap(), 1);

        let db = state.db.lock().unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn records_dns_resolution_logs_as_allowed_dns_category() {
        let state = AppState::open(":memory:").unwrap();
        let line = r#"time="2026-08-01T09:16:58.239991000+08:00" level=info msg="[UDP] mihomo --> 223.5.5.5:53 match IPCIDR(223.5.5.5/32) using DIRECT""#;
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 1);
        let db = state.db.lock().unwrap();
        let (domain, target_ip, port, decision, category, process): (
            Option<String>,
            String,
            i64,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT domain_s.value,
                        target_ip_s.value,
                        l.target_port,
                        CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                        category_s.value,
                        process_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
                   LEFT JOIN access_log_strings target_ip_s ON target_ip_s.id=l.target_ip_string_id
                   LEFT JOIN access_log_strings category_s ON category_s.id=l.category_string_id
                   LEFT JOIN access_log_strings process_s ON process_s.id=l.process_name_string_id
                  LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(domain, None);
        assert_eq!(target_ip, "223.5.5.5");
        assert_eq!(port, 53);
        assert_eq!(decision, "allow");
        assert_eq!(category, "DNS 解析");
        assert_eq!(process, "mihomo");
    }

    #[test]
    fn normalizes_legacy_dns_resolution_warnings_when_explicitly_run() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            insert_test_access_log(
                &db,
                "dns",
                "2026-08-01T09:16:58+08:00",
                "warning",
                Some(53),
                Some("DIRECT"),
            );
            normalize_dns_resolution_rows(&db).unwrap();
        }

        let stats = access_log_stats_inner(&state).unwrap();
        assert_eq!(stats.allow, 1);
        assert_eq!(stats.warning, 0);

        let db = state.db.lock().unwrap();
        let (decision, category, process): (String, String, String) = db
            .query_row(
                "SELECT CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                        category_s.value,
                        process_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings category_s ON category_s.id=l.category_string_id
                  LEFT JOIN access_log_strings process_s ON process_s.id=l.process_name_string_id
                  WHERE l.connection_hash=?1",
                params![connection_hash("dns")],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(decision, "allow");
        assert_eq!(category, "DNS 解析");
        assert_eq!(process, "mihomo");
    }

    #[test]
    fn inserts_current_mihomo_proxy_route_logfmt() {
        let state = AppState::open(":memory:").unwrap();
        let line = r#"time="2026-07-26T20:39:13.539499000+08:00" level=info msg="[TCP] 198.18.0.1:54918 --> chatgpt.com:443 match Match using CleanWeb[HK-A01]""#;
        assert_eq!(insert_mihomo_log_line(&state, line).unwrap(), 1);
        let db = state.db.lock().unwrap();
        let (domain, decision, rule, route): (String, String, String, String) = db
            .query_row(
                "SELECT domain_s.value,
                        CASE l.decision_code WHEN 1 THEN 'block' WHEN 2 THEN 'warning' ELSE 'allow' END,
                        rule_s.value,
                        route_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings domain_s ON domain_s.id=l.domain_string_id
                   LEFT JOIN access_log_strings rule_s ON rule_s.id=l.rule_string_id
                   LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
                  LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(domain, "chatgpt.com");
        assert_eq!(decision, "allow");
        assert_eq!(rule, "Match");
        assert_eq!(route, "CleanWeb[HK-A01]");
    }

    #[test]
    fn stats_count_all_access_logs_without_recent_list_limit() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        for index in 0..150 {
            insert_test_access_log(
                &db,
                &format!("allow-{index}"),
                "2026-01-01T00:00:00Z",
                "allow",
                None,
                None,
            );
        }
        for index in 0..2 {
            insert_test_access_log(
                &db,
                &format!("block-{index}"),
                "2026-01-01T00:00:00Z",
                "block",
                None,
                None,
            );
        }
        drop(db);

        let stats = access_log_stats_inner(&state).unwrap();
        assert_eq!(stats.allow, 150);
        assert_eq!(stats.block, 2);
        assert_eq!(stats.total, 152);
    }

    #[test]
    fn sqlite_orders_mixed_timezone_access_log_timestamps_by_instant() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        insert_test_access_log(
            &db,
            "old-local",
            "2026-07-26T20:29:14+08:00",
            "allow",
            None,
            Some("old-local"),
        );
        insert_test_access_log(
            &db,
            "new-utc",
            "2026-07-26T12:44:19Z",
            "allow",
            None,
            Some("new-utc"),
        );
        let first: String = db
            .query_row(
                "SELECT route_s.value
                   FROM access_logs l
                   LEFT JOIN access_log_strings route_s ON route_s.id=l.route_string_id
                  ORDER BY l.observed_at_ms DESC, l.id DESC
                  LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first, "new-utc");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn syncs_privileged_mihomo_log_file_when_available() {
        let path = Path::new(MACOS_PRIVILEGED_LOG);
        if !path.exists() {
            return;
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if !text.contains(" using REJECT") {
            return;
        }
        let state = AppState::open(":memory:").unwrap();
        assert!(sync_mihomo_log_file(&state, path).unwrap() > 0);
        let db = state.db.lock().unwrap();
        let blocks: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM access_logs WHERE decision_code=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocks > 0);
    }
}
