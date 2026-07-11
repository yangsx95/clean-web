use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Child,
    sync::Mutex,
    time::{Duration, Instant},
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::proxy_crypto::encrypt_existing_proxy_payloads;
use crate::rules::{Action, CompiledRule, MatcherKind, RuleInput};

const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

pub struct AppState {
    pub(crate) db: Mutex<Connection>,
    sessions: Mutex<HashMap<String, Instant>>,
    pub(crate) data_dir: PathBuf,
    pub(crate) core_process: Mutex<Option<Child>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapState {
    pub password_configured: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub session_token: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub protection_enabled: bool,
    pub proxy_enabled: bool,
    pub automatic_node_selection: bool,
    pub access_logging_enabled: bool,
    pub log_retention: String,
    pub categories: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRecord {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub url: String,
    pub format: Option<String>,
    pub category: Option<String>,
    pub update_interval_hours: Option<i64>,
    pub enabled: bool,
    pub last_updated_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubscription {
    pub kind: String,
    pub name: String,
    pub url: String,
    pub format: Option<String>,
    pub category: Option<String>,
    pub update_interval_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentRuleRecord {
    pub id: String,
    pub action: String,
    pub kind: String,
    pub pattern: String,
    pub category: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewParentRule {
    pub action: String,
    pub kind: String,
    pub pattern: String,
    pub category: Option<String>,
}

impl AppState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        let mut connection = Connection::open(path)?;
        initialize_schema(&connection)?;
        encrypt_existing_proxy_payloads(&mut connection).map_err(std::io::Error::other)?;
        Ok(Self {
            db: Mutex::new(connection),
            sessions: Mutex::new(HashMap::new()),
            data_dir: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            core_process: Mutex::new(None),
        })
    }

    pub(crate) fn require_session(&self, token: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|_| "会话状态不可用")?;
        let now = Instant::now();
        sessions.retain(|_, expiry| *expiry > now);
        match sessions.get_mut(token) {
            Some(expiry) => {
                *expiry = now + SESSION_TTL;
                Ok(())
            }
            None => Err("管理会话已过期，请重新解锁".into()),
        }
    }
}

fn initialize_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS app_secrets (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS subscriptions (
           id TEXT PRIMARY KEY,
           kind TEXT NOT NULL CHECK(kind IN ('rule', 'proxy')),
           name TEXT NOT NULL,
           url TEXT NOT NULL,
           format TEXT,
           category TEXT,
           update_interval_hours INTEGER,
           enabled INTEGER NOT NULL DEFAULT 1,
           last_updated_at TEXT,
           last_error TEXT,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS imported_rules (
           subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
           rule_id TEXT NOT NULL,
           matcher_kind TEXT NOT NULL,
           pattern TEXT NOT NULL,
           action TEXT NOT NULL,
           category TEXT NOT NULL,
           source_line INTEGER NOT NULL,
           PRIMARY KEY(subscription_id, rule_id)
         );
         CREATE TABLE IF NOT EXISTS proxy_payloads (
           subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
           format TEXT NOT NULL,
           payload TEXT NOT NULL,
           updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS access_logs (
           connection_id TEXT PRIMARY KEY,
           observed_at TEXT NOT NULL,
           domain TEXT,
           target_ip TEXT,
           target_port INTEGER,
           decision TEXT NOT NULL,
           rule TEXT,
           category TEXT,
           process_name TEXT,
           process_path TEXT,
           operating_system TEXT,
           system_user TEXT,
           source_ip TEXT,
           route TEXT,
           proxy_group TEXT,
           error TEXT
         );
         CREATE TABLE IF NOT EXISTS parent_rules (
           id TEXT PRIMARY KEY,
           action TEXT NOT NULL CHECK(action IN ('allow','block')),
           kind TEXT NOT NULL,
           pattern TEXT NOT NULL,
           category TEXT NOT NULL DEFAULT 'custom',
           enabled INTEGER NOT NULL DEFAULT 1,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
           UNIQUE(action,kind,pattern)
         );",
    )?;
    let defaults = [
        ("protection_enabled", "false"),
        ("proxy_enabled", "false"),
        ("automatic_node_selection", "true"),
        ("access_logging_enabled", "true"),
        ("log_retention", "30d"),
        ("category.pornography", "true"),
        ("category.gambling", "true"),
        ("category.drugs", "true"),
        ("category.violence", "true"),
        ("category.self_harm", "true"),
        ("category.hate_extremism", "true"),
        ("category.fraud", "true"),
        ("category.phishing", "true"),
        ("category.malware", "true"),
        ("category.ads", "true"),
        ("category.tracking", "true"),
    ];
    for (key, value) in defaults {
        db.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES(?1, ?2)",
            params![key, value],
        )?;
    }
    Ok(())
}

#[tauri::command]
pub fn get_bootstrap_state(state: State<'_, AppState>) -> Result<BootstrapState, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let configured = db
        .query_row(
            "SELECT 1 FROM app_secrets WHERE key='password_hash'",
            [],
            |_| Ok(true),
        )
        .optional()
        .map_err(error)?
        .unwrap_or(false);
    Ok(BootstrapState {
        password_configured: configured,
    })
}

#[tauri::command]
pub fn initialize_password(password: String, state: State<'_, AppState>) -> Result<(), String> {
    validate_password(&password)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let exists = db
        .query_row(
            "SELECT 1 FROM app_secrets WHERE key='password_hash'",
            [],
            |_| Ok(true),
        )
        .optional()
        .map_err(error)?
        .unwrap_or(false);
    if exists {
        return Err("管理密码已经设置".into());
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(error)?
        .to_string();
    db.execute(
        "INSERT INTO app_secrets(key, value) VALUES('password_hash', ?1)",
        params![hash],
    )
    .map_err(error)?;
    Ok(())
}

#[tauri::command]
pub fn unlock(password: String, state: State<'_, AppState>) -> Result<UnlockResult, String> {
    let hash = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        db.query_row(
            "SELECT value FROM app_secrets WHERE key='password_hash'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(error)?
        .ok_or("尚未设置管理密码")?
    };
    let parsed = PasswordHash::new(&hash).map_err(error)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| "管理密码错误".to_string())?;
    let token = Uuid::new_v4().to_string();
    state
        .sessions
        .lock()
        .map_err(|_| "会话状态不可用")?
        .insert(token.clone(), Instant::now() + SESSION_TTL);
    Ok(UnlockResult {
        session_token: token,
        expires_in_seconds: SESSION_TTL.as_secs(),
    })
}

#[tauri::command]
pub fn lock(session_token: String, state: State<'_, AppState>) -> Result<(), String> {
    state
        .sessions
        .lock()
        .map_err(|_| "会话状态不可用")?
        .remove(&session_token);
    Ok(())
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    read_settings(&db).map_err(error)
}

#[tauri::command]
pub fn update_setting(
    key: String,
    value: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Settings, String> {
    state.require_session(&session_token)?;
    if !allowed_setting(&key, &value) {
        return Err("不支持的设置或设置值".into());
    }
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute(
        "UPDATE settings SET value=?1 WHERE key=?2",
        params![value, key],
    )
    .map_err(error)?;
    read_settings(&db).map_err(error)
}

#[tauri::command]
pub fn list_subscriptions(
    kind: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionRecord>, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let sql = "SELECT id, kind, name, url, format, category, update_interval_hours, enabled, last_updated_at, last_error FROM subscriptions WHERE (?1 IS NULL OR kind=?1) ORDER BY created_at DESC";
    let mut statement = db.prepare(sql).map_err(error)?;
    let records = statement
        .query_map(params![kind], |row| {
            Ok(SubscriptionRecord {
                id: row.get(0)?,
                kind: row.get(1)?,
                name: row.get(2)?,
                url: row.get(3)?,
                format: row.get(4)?,
                category: row.get(5)?,
                update_interval_hours: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
                last_updated_at: row.get(8)?,
                last_error: row.get(9)?,
            })
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(records)
}

#[tauri::command]
pub fn create_subscription(
    input: NewSubscription,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionRecord, String> {
    state.require_session(&session_token)?;
    if !matches!(input.kind.as_str(), "rule" | "proxy") {
        return Err("订阅类型无效".into());
    }
    if input.name.trim().is_empty() || input.name.chars().count() > 80 {
        return Err("订阅名称无效".into());
    }
    let url = input
        .url
        .parse::<tauri::Url>()
        .map_err(|_| "订阅地址无效")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("订阅仅支持 HTTP 或 HTTPS 地址".into());
    }
    if !matches!(input.update_interval_hours, None | Some(6 | 12 | 24 | 168)) {
        return Err("更新周期无效".into());
    }
    let id = Uuid::new_v4().to_string();
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute("INSERT INTO subscriptions(id,kind,name,url,format,category,update_interval_hours) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![id, input.kind, input.name.trim(), input.url, input.format, input.category, input.update_interval_hours]).map_err(error)?;
    drop(db);
    list_subscriptions(Some(input.kind), state)?
        .into_iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "订阅保存失败".into())
}

#[tauri::command]
pub fn set_subscription_enabled(
    id: String,
    enabled: bool,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    if db
        .execute(
            "UPDATE subscriptions SET enabled=?1 WHERE id=?2",
            params![enabled, id],
        )
        .map_err(error)?
        != 1
    {
        return Err("订阅不存在".into());
    }
    Ok(())
}

#[tauri::command]
pub fn delete_subscription(
    id: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    if db
        .execute("DELETE FROM subscriptions WHERE id=?1", params![id])
        .map_err(error)?
        != 1
    {
        return Err("订阅不存在".into());
    }
    Ok(())
}

#[tauri::command]
pub fn list_parent_rules(state: State<'_, AppState>) -> Result<Vec<ParentRuleRecord>, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let mut statement=db.prepare("SELECT id,action,kind,pattern,category,enabled FROM parent_rules ORDER BY created_at DESC").map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok(ParentRuleRecord {
                id: row.get(0)?,
                action: row.get(1)?,
                kind: row.get(2)?,
                pattern: row.get(3)?,
                category: row.get(4)?,
                enabled: row.get::<_, i64>(5)? != 0,
            })
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows)
}

#[tauri::command]
pub fn create_parent_rule(
    input: NewParentRule,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<ParentRuleRecord, String> {
    state.require_session(&session_token)?;
    if input.pattern.contains([',', '\n', '\r']) {
        return Err("规则内容不能包含逗号或换行".into());
    }
    let action = match input.action.as_str() {
        "allow" => Action::Allow,
        "block" => Action::Block,
        _ => return Err("规则动作无效".into()),
    };
    let kind = match input.kind.as_str() {
        "exact" => MatcherKind::Exact,
        "suffix" => MatcherKind::Suffix,
        "contains" => MatcherKind::Contains,
        "wildcard" => MatcherKind::Wildcard,
        "regex" => MatcherKind::Regex,
        "ip" => MatcherKind::Ip,
        "cidr" => MatcherKind::Cidr,
        _ => return Err("匹配类型无效".into()),
    };
    let compiled = CompiledRule::compile(RuleInput {
        id: "validate".into(),
        action,
        priority: 30,
        kind,
        pattern: input.pattern.clone(),
        category: input.category.clone().unwrap_or_else(|| "custom".into()),
    })
    .map_err(error)?;
    let id = Uuid::new_v4().to_string();
    let kind = format!("{:?}", compiled.source.kind);
    let action = input.action;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute(
        "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES(?1,?2,?3,?4,?5)",
        params![
            id,
            action,
            kind,
            compiled.source.pattern,
            compiled.source.category
        ],
    )
    .map_err(|value| format!("规则保存失败：{value}"))?;
    drop(db);
    list_parent_rules(state)?
        .into_iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "规则保存失败".into())
}

#[tauri::command]
pub fn set_parent_rule_enabled(
    id: String,
    enabled: bool,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    if state
        .db
        .lock()
        .map_err(|_| "数据库不可用")?
        .execute(
            "UPDATE parent_rules SET enabled=?1 WHERE id=?2",
            params![enabled, id],
        )
        .map_err(error)?
        != 1
    {
        return Err("规则不存在".into());
    }
    Ok(())
}

#[tauri::command]
pub fn delete_parent_rule(
    id: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    if state
        .db
        .lock()
        .map_err(|_| "数据库不可用")?
        .execute("DELETE FROM parent_rules WHERE id=?1", params![id])
        .map_err(error)?
        != 1
    {
        return Err("规则不存在".into());
    }
    Ok(())
}

fn read_settings(db: &Connection) -> rusqlite::Result<Settings> {
    let mut statement = db.prepare("SELECT key, value FROM settings")?;
    let pairs = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    let boolean = |key: &str| pairs.get(key).is_some_and(|value| value == "true");
    let categories = pairs
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("category.")
                .map(|category| (category.to_owned(), value == "true"))
        })
        .collect();
    Ok(Settings {
        protection_enabled: boolean("protection_enabled"),
        proxy_enabled: boolean("proxy_enabled"),
        automatic_node_selection: boolean("automatic_node_selection"),
        access_logging_enabled: boolean("access_logging_enabled"),
        log_retention: pairs
            .get("log_retention")
            .cloned()
            .unwrap_or_else(|| "30d".into()),
        categories,
    })
}

fn allowed_setting(key: &str, value: &str) -> bool {
    let boolean_key = matches!(
        key,
        "protection_enabled"
            | "proxy_enabled"
            | "automatic_node_selection"
            | "access_logging_enabled"
    ) || key.starts_with("category.");
    (boolean_key && matches!(value, "true" | "false"))
        || (key == "log_retention" && matches!(value, "7d" | "30d" | "90d" | "forever"))
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 8 {
        return Err("管理密码至少需要8个字符".into());
    }
    if password.chars().count() > 128 {
        return Err("管理密码不能超过128个字符".into());
    }
    Ok(())
}

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_defaults_in_memory() {
        let state = AppState::open(":memory:").unwrap();
        let settings = read_settings(&state.db.lock().unwrap()).unwrap();
        assert!(!settings.protection_enabled);
        assert!(settings.access_logging_enabled);
        assert!(settings.categories["pornography"]);
    }

    #[test]
    fn validates_password_and_setting_allowlist() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("long-enough").is_ok());
        assert!(allowed_setting("proxy_enabled", "true"));
        assert!(allowed_setting("category.pornography", "false"));
        assert!(!allowed_setting("password_hash", "stolen"));
        assert!(!allowed_setting("proxy_enabled", "yes"));
    }
}
