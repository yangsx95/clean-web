use std::collections::HashMap;

use rusqlite::params;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    mihomo::controller_secret,
    platform,
    storage::AppState,
};

const CONTROLLER_CONNECTIONS: &str = "http://127.0.0.1:19090/connections";

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
    if !setting_bool(&state, "access_logging_enabled")? {
        return Ok(0);
    }
    let secret = controller_secret(&state)?;
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
        _ => return Ok(0),
    };
    let os = platform::os_version();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let categories = rule_categories(&state)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut inserted = 0;
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
        let decision = if rejected {
            "block"
        } else if connection.metadata.host.is_empty() {
            "warning"
        } else {
            "allow"
        };
        let category = categories.get(&connection.rule_payload).cloned();
        inserted += db.execute(
            "INSERT OR IGNORE INTO access_logs(connection_id,observed_at,domain,target_ip,target_port,decision,rule,category,process_name,process_path,operating_system,system_user,source_ip,route,proxy_group) VALUES(?1,?2,NULLIF(?3,''),NULLIF(?4,''),?5,?6,NULLIF(?7,''),?8,NULLIF(?9,''),NULLIF(?10,''),?11,?12,NULLIF(?13,''),?14,?15)",
            params![connection.id,connection.start,connection.metadata.host,connection.metadata.destination_ip,connection.metadata.destination_port.parse::<i64>().ok(),decision,connection.rule,category,connection.metadata.process,connection.metadata.process_path,os,user,connection.metadata.source_ip,route,connection.chains.first()]
        ).map_err(error)?;
    }
    cleanup_retention(&db)?;
    Ok(inserted)
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
}
