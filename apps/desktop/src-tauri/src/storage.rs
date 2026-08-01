use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Child,
    sync::{atomic::AtomicBool, Mutex},
    time::{Duration, Instant},
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;
use uuid::Uuid;

use crate::builtin_rules::{
    CLEANWEB_ADULT_SUPPLEMENT_ID, CLEANWEB_ADULT_SUPPLEMENT_TEXT, CLEANWEB_ADULT_SUPPLEMENT_URL,
    CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_ID, CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_TEXT,
    CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_URL, CLEANWEB_SECURITY_SUPPLEMENT_ID,
    CLEANWEB_SECURITY_SUPPLEMENT_TEXT, CLEANWEB_SECURITY_SUPPLEMENT_URL,
};
use crate::proxy_crypto::encrypt_existing_proxy_payloads;
#[cfg(debug_assertions)]
use crate::proxy_crypto::migrate_legacy_keychain_payloads_to_debug_key;
use crate::rules::{Action, CompiledRule, MatcherKind, RuleInput};
use crate::subscriptions::{import_text, SubscriptionFormat};

const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 小时

pub struct AppState {
    pub(crate) db: Mutex<Connection>,
    sessions: Mutex<HashMap<String, Instant>>,
    pub(crate) data_dir: PathBuf,
    pub(crate) core_process: Mutex<Option<Child>>,
    pub(crate) reload_in_progress: AtomicBool,
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
    pub safe_search_enabled: bool,
    pub strict_mode_enabled: bool,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubscription {
    pub name: String,
    pub url: String,
    pub format: Option<String>,
    pub category: Option<String>,
    pub update_interval_hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedSource {
    pub name: String,
    pub url: String,
    pub format: String,
    pub category: String,
    pub description: String,
}

/// 返回内置推荐规则源列表，供用户在添加订阅时快速选择
pub fn get_recommended_rule_sources() -> Vec<RecommendedSource> {
    vec![
        // ── hosts 格式 ──
        RecommendedSource {
            name: "综合广告与恶意软件".into(),
            url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
            format: "hosts".into(),
            category: "ads".into(),
            description: "Steven Black 维护的合并去重 hosts 列表，覆盖广告、恶意软件与跟踪域名".into(),
        },
        RecommendedSource {
            name: "AdAway 广告拦截".into(),
            url: "https://adaway.org/hosts.txt".into(),
            format: "hosts".into(),
            category: "ads".into(),
            description: "AdAway 官方 hosts 列表，专注移动广告拦截".into(),
        },
        RecommendedSource {
            name: "Dan Pollock hosts".into(),
            url: "https://someonewhocares.org/hosts/zero/hosts".into(),
            format: "hosts".into(),
            category: "ads".into(),
            description: "Dan Pollock 维护的经典 hosts 列表，拦截广告与跟踪域名".into(),
        },
        RecommendedSource {
            name: "赌博网站拦截".into(),
            url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts".into(),
            format: "hosts".into(),
            category: "gambling".into(),
            description: "Steven Black 赌博分类 hosts 列表".into(),
        },
        RecommendedSource {
            name: "色情内容拦截".into(),
            url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts".into(),
            format: "hosts".into(),
            category: "pornography".into(),
            description: "Steven Black 色情分类 hosts 列表".into(),
        },
        RecommendedSource {
            name: "恶意软件域名".into(),
            url: "https://urlhaus.abuse.ch/downloads/hostfile/".into(),
            format: "hosts".into(),
            category: "malware".into(),
            description: "URLhaus 实时恶意软件分发域名列表".into(),
        },
        // ── adblock 格式 ──
        RecommendedSource {
            name: "EasyList 广告过滤".into(),
            url: "https://easylist.to/easylist/easylist.txt".into(),
            format: "adblock".into(),
            category: "ads".into(),
            description: "Adblock 生态中最广泛使用的英文广告过滤列表".into(),
        },
        RecommendedSource {
            name: "EasyList China".into(),
            url: "https://easylist-downloads.adblockplus.org/easylistchina.txt".into(),
            format: "adblock".into(),
            category: "ads".into(),
            description: "EasyList 中文补充规则，覆盖国内网站广告".into(),
        },
        RecommendedSource {
            name: "AdGuard 中文过滤".into(),
            url: "https://filters.adtidy.org/extension/chromium/filters/224.txt".into(),
            format: "adblock".into(),
            category: "ads".into(),
            description: "AdGuard 维护的中文广告过滤规则".into(),
        },
        RecommendedSource {
            name: "uBlock 隐私保护".into(),
            url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt".into(),
            format: "adblock".into(),
            category: "ads".into(),
            description: "uBlock Origin 隐私保护规则，拦截跟踪器和指纹收集".into(),
        },
        // ── domain-list 格式 ──
        RecommendedSource {
            name: "Loyalsoldier 直连域名".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt".into(),
            format: "domain-list".into(),
            category: "direct".into(),
            description: "国内常用域名直连列表，避免不必要的代理".into(),
        },
        RecommendedSource {
            name: "GFW 域名列表".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt".into(),
            format: "domain-list".into(),
            category: "routing".into(),
            description: "常见被封锁域名列表，用于精确代理".into(),
        },
        RecommendedSource {
            name: "广告域名列表".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt".into(),
            format: "domain-list".into(),
            category: "ads".into(),
            description: "广告与跟踪域名列表，纯域名格式".into(),
        },
        // ── ip-list 格式 ──
        RecommendedSource {
            name: "中国 IP 地址段".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt".into(),
            format: "clash".into(),
            category: "direct".into(),
            description: "中国大陆 IP 地址段，用于直连或分流策略".into(),
        },
        RecommendedSource {
            name: "恶意 IP 地址段".into(),
            url: "https://www.spamhaus.org/drop/drop.txt".into(),
            format: "ip-list".into(),
            category: "malware".into(),
            description: "Spamhaus DROP 列表，已知恶意网络地址段".into(),
        },
        RecommendedSource {
            name: "私有 IP 地址段".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/private.txt".into(),
            format: "ip-list".into(),
            category: "custom".into(),
            description: "私有与保留 IP 地址段，确保内网流量直连".into(),
        },
        // ── clash 格式 ──
        RecommendedSource {
            name: "Loyalsoldier Clash 规则".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt".into(),
            format: "clash".into(),
            category: "ads".into(),
            description: "Loyalsoldier 维护的 Clash 广告拦截规则集".into(),
        },
        RecommendedSource {
            name: "Clash 域名直连规则".into(),
            url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt".into(),
            format: "clash".into(),
            category: "direct".into(),
            description: "Clash 格式的国内直连域名规则".into(),
        },
    ]
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
        #[cfg(debug_assertions)]
        migrate_legacy_keychain_payloads_to_debug_key(&mut connection)
            .map_err(std::io::Error::other)?;
        encrypt_existing_proxy_payloads(&mut connection).map_err(std::io::Error::other)?;
        Ok(Self {
            db: Mutex::new(connection),
            sessions: Mutex::new(HashMap::new()),
            data_dir: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            core_process: Mutex::new(None),
            reload_in_progress: AtomicBool::new(false),
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
         CREATE TABLE IF NOT EXISTS access_log_strings (
           id INTEGER PRIMARY KEY,
           value TEXT NOT NULL UNIQUE
         );
         CREATE TABLE IF NOT EXISTS access_logs (
           id INTEGER PRIMARY KEY,
           connection_hash BLOB NOT NULL UNIQUE,
           observed_at_ms INTEGER NOT NULL,
           domain_string_id INTEGER REFERENCES access_log_strings(id),
           target_ip_string_id INTEGER REFERENCES access_log_strings(id),
           target_port INTEGER,
           decision_code INTEGER NOT NULL,
           rule_string_id INTEGER REFERENCES access_log_strings(id),
           category_string_id INTEGER REFERENCES access_log_strings(id),
           process_name_string_id INTEGER REFERENCES access_log_strings(id),
           process_path_string_id INTEGER REFERENCES access_log_strings(id),
           operating_system_string_id INTEGER REFERENCES access_log_strings(id),
           system_user_string_id INTEGER REFERENCES access_log_strings(id),
           source_ip_string_id INTEGER REFERENCES access_log_strings(id),
           route_string_id INTEGER REFERENCES access_log_strings(id),
           proxy_group_string_id INTEGER REFERENCES access_log_strings(id),
           error_string_id INTEGER REFERENCES access_log_strings(id)
         );
         CREATE TABLE IF NOT EXISTS parent_rules (
           id TEXT PRIMARY KEY,
           action TEXT NOT NULL CHECK(action IN ('allow','block','proxy','system_route')),
           kind TEXT NOT NULL,
           pattern TEXT NOT NULL,
           category TEXT NOT NULL DEFAULT 'custom',
           enabled INTEGER NOT NULL DEFAULT 1,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
           UNIQUE(action,kind,pattern)
         );
         CREATE TABLE IF NOT EXISTS proxy_selections (
           group_name TEXT PRIMARY KEY,
           proxy_name TEXT NOT NULL,
           updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS safe_search_mappings (
           subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
           domain TEXT NOT NULL,
           target TEXT NOT NULL,
           source_line INTEGER NOT NULL,
           PRIMARY KEY(subscription_id,domain)
         );",
    )?;
    migrate_parent_rules_action_constraint(db)?;
    migrate_access_log_string_storage(db)?;
    if migrate_compact_access_logs(db)? {
        db.execute_batch("VACUUM")?;
    }
    let defaults = [
        ("protection_enabled", "false"),
        ("proxy_enabled", "false"),
        ("automatic_node_selection", "true"),
        ("access_logging_enabled", "true"),
        ("safe_search_enabled", "true"),
        ("strict_mode_enabled", "false"),
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
        ("category.entertainment", "false"),
    ];
    for (key, value) in defaults {
        db.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES(?1, ?2)",
            params![key, value],
        )?;
    }
    seed_default_rule_subscriptions(db)?;
    Ok(())
}

fn seed_default_rule_subscriptions(db: &Connection) -> rusqlite::Result<()> {
    const SEED_MARKER: &str = "builtin_rule_sources_v5_seeded";
    db.execute(
        "UPDATE subscriptions SET enabled=1 WHERE id LIKE 'default:%' OR url LIKE 'builtin://%'",
        [],
    )?;
    let sources = [
        (
            "default:stevenblack:porn",
            "内置规则 · 色情内容",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
            "hosts",
            "pornography",
        ),
        (
            "default:stevenblack:gambling",
            "内置规则 · 赌博网站",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
            "hosts",
            "gambling",
        ),
        (
            "default:blocklistproject:drugs",
            "内置规则 · 毒品网站",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/drugs-nl.txt",
            "domain-list",
            "drugs",
        ),
        (
            "default:blocklistproject:fraud",
            "内置规则 · 诈骗网站",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/fraud-nl.txt",
            "domain-list",
            "fraud",
        ),
        (
            "default:blocklistproject:phishing",
            "内置规则 · 钓鱼网站",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/phishing-nl.txt",
            "domain-list",
            "phishing",
        ),
        (
            "default:urlhaus:malware",
            "内置规则 · 恶意软件",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "hosts",
            "malware",
        ),
        (
            CLEANWEB_ADULT_SUPPLEMENT_ID,
            "内置规则 · 成人站点补充",
            CLEANWEB_ADULT_SUPPLEMENT_URL,
            "clash",
            "pornography",
        ),
        (
            CLEANWEB_SECURITY_SUPPLEMENT_ID,
            "内置规则 · DNS 防绕过",
            CLEANWEB_SECURITY_SUPPLEMENT_URL,
            "clash",
            "phishing",
        ),
        (
            CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_ID,
            "内置规则 · 娱乐 CDN 补充",
            CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_URL,
            "clash",
            "entertainment",
        ),
        (
            "default:loyalsoldier:cncidr",
            "内置路由 · 中国 IP 直连",
            "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",
            "clash",
            "direct",
        ),
    ];
    for (id, name, url, format, category) in sources {
        db.execute(
            "UPDATE subscriptions SET name=?2,url=?3,format=?4,category=?5,update_interval_hours=CASE WHEN ?3 LIKE 'builtin://%' THEN NULL ELSE 24 END WHERE id=?1 AND kind='rule'",
            params![id, name, url, format, category],
        )?;
    }

    db.execute(
        "DELETE FROM settings WHERE key LIKE 'deleted_default_source.%'",
        [],
    )?;
    // Remove the short-lived v1 entries whose upstream paths no longer exist.
    db.execute(
        "DELETE FROM subscriptions WHERE id LIKE 'builtin:blackmatrix7:%' OR id='default:blocklistproject:malware'",
        [],
    )?;

    for (id, name, url, format, category) in sources {
        db.execute(
            "INSERT OR IGNORE INTO subscriptions(
               id,kind,name,url,format,category,update_interval_hours,enabled
             ) VALUES(?1,'rule',?2,?3,?4,?5,CASE WHEN ?3 LIKE 'builtin://%' THEN NULL ELSE 24 END,1)",
            params![id, name, url, format, category],
        )?;
    }
    seed_builtin_rule_text(
        db,
        CLEANWEB_ADULT_SUPPLEMENT_ID,
        CLEANWEB_ADULT_SUPPLEMENT_URL,
        "pornography",
        CLEANWEB_ADULT_SUPPLEMENT_TEXT,
    )?;
    seed_builtin_rule_text(
        db,
        CLEANWEB_SECURITY_SUPPLEMENT_ID,
        CLEANWEB_SECURITY_SUPPLEMENT_URL,
        "phishing",
        CLEANWEB_SECURITY_SUPPLEMENT_TEXT,
    )?;
    seed_builtin_rule_text(
        db,
        CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_ID,
        CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_URL,
        "entertainment",
        CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_TEXT,
    )?;
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value) VALUES(?1,'true')",
        params![SEED_MARKER],
    )?;
    Ok(())
}

fn seed_builtin_rule_text(
    db: &Connection,
    id: &str,
    url: &str,
    category: &str,
    text: &str,
) -> rusqlite::Result<()> {
    let imported = import_text(SubscriptionFormat::Clash, text, id, url, category);
    let transaction = db.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM imported_rules WHERE subscription_id=?1",
        params![id],
    )?;
    for item in imported.rules {
        transaction.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,item.rule.id,format!("{:?}",item.rule.kind),item.rule.pattern,format!("{:?}",item.rule.action),item.rule.category,item.source.source_line as i64])?;
    }
    transaction.commit()
}

fn migrate_parent_rules_action_constraint(db: &Connection) -> rusqlite::Result<()> {
    let table_sql: Option<String> = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='parent_rules'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if table_sql
        .as_deref()
        .is_some_and(|sql| sql.contains("'system_route'"))
    {
        return Ok(());
    }
    db.execute_batch(
        "ALTER TABLE parent_rules RENAME TO parent_rules_old;
         CREATE TABLE parent_rules (
           id TEXT PRIMARY KEY,
           action TEXT NOT NULL CHECK(action IN ('allow','block','proxy','system_route')),
           kind TEXT NOT NULL,
           pattern TEXT NOT NULL,
           category TEXT NOT NULL DEFAULT 'custom',
           enabled INTEGER NOT NULL DEFAULT 1,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
           UNIQUE(action,kind,pattern)
         );
         INSERT OR IGNORE INTO parent_rules(id,action,kind,pattern,category,enabled,created_at)
           SELECT id,action,kind,pattern,category,enabled,created_at FROM parent_rules_old;
         DROP TABLE parent_rules_old;",
    )
}

fn migrate_access_log_string_storage(db: &Connection) -> rusqlite::Result<()> {
    db.execute(
        "CREATE TABLE IF NOT EXISTS access_log_strings (
           id INTEGER PRIMARY KEY,
           value TEXT NOT NULL UNIQUE
         )",
        [],
    )?;
    let columns = [
        ("rule", "rule_string_id"),
        ("category", "category_string_id"),
        ("process_name", "process_name_string_id"),
        ("process_path", "process_path_string_id"),
        ("operating_system", "operating_system_string_id"),
        ("system_user", "system_user_string_id"),
        ("source_ip", "source_ip_string_id"),
        ("route", "route_string_id"),
        ("proxy_group", "proxy_group_string_id"),
        ("error", "error_string_id"),
    ];
    for (_, id_column) in columns {
        add_access_log_string_column(db, id_column)?;
    }
    for (text_column, id_column) in columns {
        if !table_has_column(db, "access_logs", text_column)? {
            continue;
        }
        db.execute(
            &format!(
                "INSERT OR IGNORE INTO access_log_strings(value)
                   SELECT DISTINCT {text_column}
                   FROM access_logs
                  WHERE {text_column} IS NOT NULL AND {text_column}<>''"
            ),
            [],
        )?;
        db.execute(
            &format!(
                "UPDATE access_logs
                    SET {id_column}=(SELECT id FROM access_log_strings WHERE value={text_column}),
                        {text_column}=NULL
                  WHERE {text_column} IS NOT NULL AND {text_column}<>''"
            ),
            [],
        )?;
    }
    Ok(())
}

fn add_access_log_string_column(db: &Connection, column: &str) -> rusqlite::Result<()> {
    if !table_has_column(db, "access_logs", column)? {
        db.execute(
            &format!("ALTER TABLE access_logs ADD COLUMN {column} INTEGER REFERENCES access_log_strings(id)"),
            [],
        )?;
    }
    Ok(())
}

fn table_has_column(db: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    Ok(db
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .any(|name| name == column))
}

fn migrate_compact_access_logs(db: &Connection) -> rusqlite::Result<bool> {
    if table_has_column(db, "access_logs", "observed_at_ms")? {
        return Ok(false);
    }
    if !table_has_column(db, "access_logs", "connection_id")? {
        return Ok(false);
    }
    db.execute(
        "INSERT OR IGNORE INTO access_log_strings(value)
           SELECT DISTINCT domain FROM access_logs WHERE domain IS NOT NULL AND domain<>''",
        [],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO access_log_strings(value)
           SELECT DISTINCT target_ip FROM access_logs WHERE target_ip IS NOT NULL AND target_ip<>''",
        [],
    )?;
    db.execute(
        "CREATE TABLE access_logs_compact (
           id INTEGER PRIMARY KEY,
           connection_hash BLOB NOT NULL UNIQUE,
           observed_at_ms INTEGER NOT NULL,
           domain_string_id INTEGER REFERENCES access_log_strings(id),
           target_ip_string_id INTEGER REFERENCES access_log_strings(id),
           target_port INTEGER,
           decision_code INTEGER NOT NULL,
           rule_string_id INTEGER REFERENCES access_log_strings(id),
           category_string_id INTEGER REFERENCES access_log_strings(id),
           process_name_string_id INTEGER REFERENCES access_log_strings(id),
           process_path_string_id INTEGER REFERENCES access_log_strings(id),
           operating_system_string_id INTEGER REFERENCES access_log_strings(id),
           system_user_string_id INTEGER REFERENCES access_log_strings(id),
           source_ip_string_id INTEGER REFERENCES access_log_strings(id),
           route_string_id INTEGER REFERENCES access_log_strings(id),
           proxy_group_string_id INTEGER REFERENCES access_log_strings(id),
           error_string_id INTEGER REFERENCES access_log_strings(id)
         )",
        [],
    )?;
    struct Row {
        connection_id: String,
        observed_at_ms: i64,
        domain_id: Option<i64>,
        target_ip_id: Option<i64>,
        target_port: Option<i64>,
        decision_code: i64,
        rule_id: Option<i64>,
        category_id: Option<i64>,
        process_name_id: Option<i64>,
        process_path_id: Option<i64>,
        operating_system_id: Option<i64>,
        system_user_id: Option<i64>,
        source_ip_id: Option<i64>,
        route_id: Option<i64>,
        proxy_group_id: Option<i64>,
        error_id: Option<i64>,
    }
    let rows = {
        let mut statement = db.prepare(
            "SELECT l.connection_id,
                    CAST(COALESCE((julianday(l.observed_at)-2440587.5)*86400000,(julianday('now')-2440587.5)*86400000) AS INTEGER),
                    domain_s.id,
                    target_ip_s.id,
                    l.target_port,
                    CASE l.decision WHEN 'block' THEN 1 WHEN 'warning' THEN 2 ELSE 0 END,
                    l.rule_string_id,l.category_string_id,l.process_name_string_id,l.process_path_string_id,
                    l.operating_system_string_id,l.system_user_string_id,l.source_ip_string_id,
                    l.route_string_id,l.proxy_group_string_id,l.error_string_id
               FROM access_logs l
               LEFT JOIN access_log_strings domain_s ON domain_s.value=l.domain
               LEFT JOIN access_log_strings target_ip_s ON target_ip_s.value=l.target_ip",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(Row {
                    connection_id: row.get(0)?,
                    observed_at_ms: row.get(1)?,
                    domain_id: row.get(2)?,
                    target_ip_id: row.get(3)?,
                    target_port: row.get(4)?,
                    decision_code: row.get(5)?,
                    rule_id: row.get(6)?,
                    category_id: row.get(7)?,
                    process_name_id: row.get(8)?,
                    process_path_id: row.get(9)?,
                    operating_system_id: row.get(10)?,
                    system_user_id: row.get(11)?,
                    source_ip_id: row.get(12)?,
                    route_id: row.get(13)?,
                    proxy_group_id: row.get(14)?,
                    error_id: row.get(15)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    db.execute_batch("BEGIN IMMEDIATE")?;
    let insert_result = (|| {
        let mut insert = db.prepare(
            "INSERT OR IGNORE INTO access_logs_compact(connection_hash,observed_at_ms,domain_string_id,target_ip_string_id,target_port,decision_code,rule_string_id,category_string_id,process_name_string_id,process_path_string_id,operating_system_string_id,system_user_string_id,source_ip_string_id,route_string_id,proxy_group_string_id,error_string_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        )?;
        for row in rows {
            let hash = Sha256::digest(row.connection_id.as_bytes())[..8].to_vec();
            insert.execute(params![
                hash,
                row.observed_at_ms,
                row.domain_id,
                row.target_ip_id,
                row.target_port,
                row.decision_code,
                row.rule_id,
                row.category_id,
                row.process_name_id,
                row.process_path_id,
                row.operating_system_id,
                row.system_user_id,
                row.source_ip_id,
                row.route_id,
                row.proxy_group_id,
                row.error_id
            ])?;
        }
        Ok::<(), rusqlite::Error>(())
    })();
    if insert_result.is_ok() {
        db.execute_batch(
            "DROP TABLE access_logs;
             ALTER TABLE access_logs_compact RENAME TO access_logs;",
        )?;
        db.execute_batch("COMMIT")?;
    } else {
        db.execute_batch("ROLLBACK")?;
        insert_result?;
    }
    Ok(true)
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

pub(crate) fn verify_management_password(password: &str, state: &AppState) -> Result<(), String> {
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
        .map_err(|_| "管理密码错误".to_string())
}

#[tauri::command]
pub fn verify_password(password: String, state: State<'_, AppState>) -> Result<(), String> {
    verify_management_password(&password, &state)
}

#[tauri::command]
pub fn unlock(password: String, state: State<'_, AppState>) -> Result<UnlockResult, String> {
    verify_management_password(&password, &state)?;
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
pub fn validate_session(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<UnlockResult, String> {
    state.require_session(&session_token)?;
    Ok(UnlockResult {
        session_token,
        expires_in_seconds: SESSION_TTL.as_secs(),
    })
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
    if key == "proxy_enabled" && value == "true" {
        let usable_payloads: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM proxy_payloads pp JOIN subscriptions s ON s.id=pp.subscription_id WHERE s.enabled=1 AND s.kind='proxy' AND pp.format='clash'",
                [],
                |row| row.get(0),
            )
            .map_err(error)?;
        if usable_payloads == 0 {
            return Err("请先导入包含可用节点的 Clash/Mihomo 代理订阅".into());
        }
    }
    db.execute(
        "UPDATE settings SET value=?1 WHERE key=?2",
        params![value, key],
    )
    .map_err(error)?;
    let result = read_settings(&db).map_err(error)?;
    drop(db);
    Ok(result)
}

#[tauri::command]
pub fn list_subscriptions(
    session_token: String,
    kind: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionRecord>, String> {
    state.require_session(&session_token)?;
    list_subscriptions_inner(kind, &state)
}

fn list_subscriptions_inner(
    kind: Option<String>,
    state: &AppState,
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

fn validate_subscription_fields(
    name: &str,
    url: &str,
    update_interval_hours: Option<i64>,
) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 80 {
        return Err("订阅名称无效".into());
    }
    let url = url.parse::<tauri::Url>().map_err(|_| "订阅地址无效")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("订阅仅支持 HTTP 或 HTTPS 地址".into());
    }
    if !matches!(update_interval_hours, None | Some(6 | 12 | 24 | 168)) {
        return Err("更新周期无效".into());
    }
    Ok(())
}

fn is_builtin_subscription_record(id: &str, _name: &str, url: &str) -> bool {
    id.starts_with("default:") || url.starts_with("builtin://")
}

fn require_mutable_subscription(db: &Connection, id: &str) -> Result<(), String> {
    if id.starts_with("default:") {
        return Err("内置规则不能修改".into());
    }
    let record = db
        .query_row(
            "SELECT name,url FROM subscriptions WHERE id=?1",
            params![id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(error)?
        .ok_or_else(|| "订阅不存在".to_string())?;
    if is_builtin_subscription_record(id, &record.0, &record.1) {
        return Err("内置规则不能修改".into());
    }
    Ok(())
}

fn require_deletable_subscription(db: &Connection, id: &str) -> Result<(), String> {
    if id.starts_with("default:") {
        return Err("内置规则不能删除".into());
    }
    let record = db
        .query_row(
            "SELECT name,url FROM subscriptions WHERE id=?1",
            params![id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(error)?
        .ok_or_else(|| "订阅不存在".to_string())?;
    if is_builtin_subscription_record(id, &record.0, &record.1) {
        return Err("内置规则不能删除".into());
    }
    Ok(())
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
    validate_subscription_fields(&input.name, &input.url, input.update_interval_hours)?;
    let id = Uuid::new_v4().to_string();
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.execute("INSERT INTO subscriptions(id,kind,name,url,format,category,update_interval_hours) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![id, input.kind, input.name.trim(), input.url, input.format, input.category, input.update_interval_hours]).map_err(error)?;
    drop(db);
    list_subscriptions_inner(Some(input.kind), &state)?
        .into_iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "订阅保存失败".into())
}

#[tauri::command]
pub fn update_subscription(
    id: String,
    input: UpdateSubscription,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionRecord, String> {
    state.require_session(&session_token)?;
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    require_mutable_subscription(&db, &id)?;
    validate_subscription_fields(&input.name, &input.url, input.update_interval_hours)?;
    let kind = update_subscription_inner(&db, &id, &input)?;
    drop(db);
    list_subscriptions_inner(Some(kind), &state)?
        .into_iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "订阅保存失败".into())
}

fn update_subscription_inner(
    db: &Connection,
    id: &str,
    input: &UpdateSubscription,
) -> Result<String, String> {
    require_mutable_subscription(db, id)?;
    validate_subscription_fields(&input.name, &input.url, input.update_interval_hours)?;
    let kind: String = db
        .query_row(
            "SELECT kind FROM subscriptions WHERE id=?1",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .map_err(error)?
        .ok_or_else(|| "订阅不存在".to_string())?;
    if db
        .execute(
            "UPDATE subscriptions SET name=?2,url=?3,format=?4,category=?5,update_interval_hours=?6,last_error=NULL WHERE id=?1",
            params![
                id,
                input.name.trim(),
                &input.url,
                &input.format,
                &input.category,
                input.update_interval_hours
            ],
        )
        .map_err(error)?
        != 1
    {
        return Err("订阅不存在".into());
    }
    Ok(kind)
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
    if !enabled {
        if id.starts_with("default:") {
            return Err("内置规则必须保持启用".into());
        }
        let record = db
            .query_row(
                "SELECT name,url FROM subscriptions WHERE id=?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(error)?
            .ok_or_else(|| "订阅不存在".to_string())?;
        if is_builtin_subscription_record(&id, &record.0, &record.1) {
            return Err("内置规则必须保持启用".into());
        }
    }
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
    drop(db);
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
    require_deletable_subscription(&db, &id)?;
    delete_subscription_inner(&db, &id)?;
    drop(db);
    Ok(())
}

fn delete_subscription_inner(db: &Connection, id: &str) -> Result<(), String> {
    require_deletable_subscription(db, id)?;
    let transaction = db.unchecked_transaction().map_err(error)?;
    if transaction
        .execute("DELETE FROM subscriptions WHERE id=?1", params![id])
        .map_err(error)?
        != 1
    {
        return Err("订阅不存在".into());
    }
    transaction.commit().map_err(error)
}

#[tauri::command]
pub fn get_recommended_sources() -> Vec<RecommendedSource> {
    get_recommended_rule_sources()
}

#[tauri::command]
pub fn list_parent_rules(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<ParentRuleRecord>, String> {
    state.require_session(&session_token)?;
    list_parent_rules_inner(&state)
}

fn list_parent_rules_inner(state: &AppState) -> Result<Vec<ParentRuleRecord>, String> {
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
        "proxy" => Action::Proxy,
        "system_route" => Action::SystemRoute,
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
    list_parent_rules_inner(&state)?
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
        safe_search_enabled: boolean("safe_search_enabled"),
        strict_mode_enabled: boolean("strict_mode_enabled"),
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
            | "safe_search_enabled"
            | "strict_mode_enabled"
    ) || matches!(
        key,
        "category.ads" | "category.tracking" | "category.entertainment"
    );
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
        assert!(!settings.strict_mode_enabled);
        assert!(settings.access_logging_enabled);
        assert!(settings.categories["pornography"]);
        assert!(!settings.categories["entertainment"]);
    }

    #[test]
    fn validates_password_and_setting_allowlist() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("long-enough").is_ok());
        assert!(allowed_setting("proxy_enabled", "true"));
        assert!(allowed_setting("safe_search_enabled", "true"));
        assert!(allowed_setting("safe_search_enabled", "false"));
        assert!(allowed_setting("strict_mode_enabled", "true"));
        assert!(allowed_setting("strict_mode_enabled", "false"));
        assert!(!allowed_setting("safe_search_enabled", "yes"));
        assert!(!allowed_setting("strict_mode_enabled", "yes"));
        assert!(!allowed_setting("category.pornography", "false"));
        assert!(!allowed_setting("category.malware", "false"));
        assert!(allowed_setting("category.ads", "false"));
        assert!(allowed_setting("category.tracking", "false"));
        assert!(allowed_setting("category.entertainment", "false"));
        assert!(!allowed_setting("password_hash", "stolen"));
        assert!(!allowed_setting("proxy_enabled", "yes"));
    }

    #[test]
    fn parent_rules_allow_proxy_and_system_route_actions() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('p','proxy','Exact','example.com','custom')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('s','system_route','Exact','internal.example','routing')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn recommended_sources_have_valid_fields() {
        let sources = get_recommended_rule_sources();
        assert!(!sources.is_empty(), "推荐源列表不应为空");
        let valid_categories = [
            "ads",
            "pornography",
            "gambling",
            "malware",
            "custom",
            "direct",
            "routing",
        ];
        let valid_formats = ["hosts", "adblock", "domain-list", "ip-list", "clash"];
        for src in &sources {
            assert!(!src.name.is_empty(), "名称不应为空");
            assert!(src.url.starts_with("http"), "URL 应为 HTTP(S): {}", src.url);
            assert!(
                valid_formats.contains(&src.format.as_str()),
                "无效格式: {}",
                src.format
            );
            assert!(
                valid_categories.contains(&src.category.as_str()),
                "无效分类: {}",
                src.category
            );
            assert!(!src.description.is_empty(), "描述不应为空");
        }
    }

    #[test]
    fn seeds_known_default_rule_sources_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cleanweb.db");
        {
            let state = AppState::open(&path).unwrap();
            let db = state.db.lock().unwrap();
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM subscriptions WHERE id LIKE 'default:%' AND enabled=1 AND update_interval_hours=24",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 7);
            assert!(delete_subscription_inner(&db, "default:blocklistproject:fraud").is_err());
        }

        let state = AppState::open(&path).unwrap();
        let db = state.db.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM subscriptions WHERE id LIKE 'default:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 9, "default 内置规则必须始终存在");
        let builtin_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM subscriptions WHERE url LIKE 'builtin://%' AND enabled=1 AND update_interval_hours IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(builtin_count, 3, "打包规则不应参与网络刷新");
        let imported_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM imported_rules WHERE subscription_id LIKE 'default:cleanweb:%' OR subscription_id='local:cleanweb:entertainment-cdn'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(imported_count > 0, "打包规则必须写入可执行规则表");
    }

    #[test]
    fn default_sources_are_restored_and_forced_enabled() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute(
            "UPDATE subscriptions SET enabled=0 WHERE id='default:stevenblack:porn'",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE subscriptions SET url='https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/cncidr.txt',format='ip-list',category='custom' WHERE id='default:loyalsoldier:cncidr'",
            [],
        )
        .unwrap();
        db.execute(
            "DELETE FROM settings WHERE key='builtin_rule_sources_v4_seeded'",
            [],
        )
        .unwrap();
        seed_default_rule_subscriptions(&db).unwrap();
        let enabled: i64 = db
            .query_row(
                "SELECT enabled FROM subscriptions WHERE id='default:stevenblack:porn'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enabled, 1, "内置规则必须恢复启用");
        let (url, format, category): (String, String, String) = db
            .query_row(
                "SELECT url,format,category FROM subscriptions WHERE id='default:loyalsoldier:cncidr'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt"
        );
        assert_eq!(format, "clash");
        assert_eq!(category, "direct");
        assert!(delete_subscription_inner(&db, "default:stevenblack:porn").is_err());
    }

    #[test]
    fn updates_external_subscription_metadata() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO subscriptions(id,kind,name,url,format,category,update_interval_hours,last_error) VALUES('custom-source','rule','旧规则','https://example.test/old','hosts','custom',24,'上次失败')",
            [],
        )
        .unwrap();

        let kind = update_subscription_inner(
            &db,
            "custom-source",
            &UpdateSubscription {
                name: " 新规则 ".into(),
                url: "https://example.test/new".into(),
                format: Some("adblock".into()),
                category: Some("ads".into()),
                update_interval_hours: Some(12),
            },
        )
        .unwrap();

        assert_eq!(kind, "rule");
        let (name, url, format, category, interval, last_error): (
            String,
            String,
            String,
            String,
            i64,
            Option<String>,
        ) = db
            .query_row(
                "SELECT name,url,format,category,update_interval_hours,last_error FROM subscriptions WHERE id='custom-source'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .unwrap();
        assert_eq!(name, "新规则");
        assert_eq!(url, "https://example.test/new");
        assert_eq!(format, "adblock");
        assert_eq!(category, "ads");
        assert_eq!(interval, 12);
        assert_eq!(last_error, None);
    }

    #[test]
    fn rejects_default_subscription_updates() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        let result = update_subscription_inner(
            &db,
            "default:stevenblack:porn",
            &UpdateSubscription {
                name: "不应修改".into(),
                url: "https://example.test/new".into(),
                format: Some("hosts".into()),
                category: Some("pornography".into()),
                update_interval_hours: Some(24),
            },
        );

        assert_eq!(result.unwrap_err(), "内置规则不能修改");
    }

    #[test]
    fn rejects_builtin_url_subscription_mutation() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO subscriptions(id,kind,name,url,format,category,enabled) VALUES('legacy-builtin-url','rule','娱乐 CDN','builtin://cleanweb/entertainment-cdn','clash','entertainment',1)",
            [],
        )
        .unwrap();

        let update_result = update_subscription_inner(
            &db,
            "legacy-builtin-url",
            &UpdateSubscription {
                name: "不应修改".into(),
                url: "https://example.test/new".into(),
                format: Some("hosts".into()),
                category: Some("custom".into()),
                update_interval_hours: Some(24),
            },
        );
        let delete_result = delete_subscription_inner(&db, "legacy-builtin-url");

        assert_eq!(update_result.unwrap_err(), "内置规则不能修改");
        assert_eq!(delete_result.unwrap_err(), "内置规则不能删除");
    }

    #[test]
    fn default_sources_are_restored_after_seed_marker_exists() {
        let state = AppState::open(":memory:").unwrap();
        let db = state.db.lock().unwrap();
        db.execute(
            "DELETE FROM subscriptions WHERE id='default:stevenblack:porn'",
            [],
        )
        .unwrap();
        seed_default_rule_subscriptions(&db).unwrap();
        let name: String = db
            .query_row(
                "SELECT name FROM subscriptions WHERE id='default:stevenblack:porn'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "内置规则 · 色情内容");
    }
}
