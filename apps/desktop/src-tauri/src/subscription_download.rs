use std::{fs, path::PathBuf, time::Duration};

use reqwest::{
    header::{
        CACHE_CONTROL, CONTENT_LENGTH, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
        PRAGMA,
    },
    StatusCode,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::{
    proxy_crypto::encrypt_proxy_payload,
    storage::{AppState, SubscriptionRecord},
    subscriptions::{import_safe_search_mappings, import_text, SubscriptionFormat},
};

const MAX_SUBSCRIPTION_BYTES: usize = 20 * 1024 * 1024;
const SUBSCRIPTION_PROGRESS_EVENT: &str = "subscription-refresh-progress";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReport {
    pub detected_format: String,
    pub imported_count: usize,
    pub ignored_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
    pub updated: bool,
}

#[derive(Debug)]
struct RefreshOutcome {
    report: RefreshReport,
    changed: bool,
}

#[derive(Debug)]
enum DownloadOutcome {
    NotModified,
    Downloaded {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSourceRefreshReport {
    pub checked_count: usize,
    pub updated_count: usize,
    pub unchanged_count: usize,
    pub failed_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRefreshProgress {
    pub id: String,
    pub phase: String,
    pub downloaded_bytes: usize,
    pub total_bytes: Option<usize>,
    pub percent: Option<u8>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualProxyImport {
    name: String,
    content: String,
}

#[tauri::command]
pub async fn refresh_subscription(
    id: String,
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<RefreshReport, String> {
    state.require_session(&session_token)?;
    let outcome = refresh_subscription_inner(id, &state, Some(&app)).await?;
    let mut report = outcome.report;
    report.updated = outcome.changed;
    Ok(report)
}

async fn refresh_subscription_inner(
    id: String,
    state: &AppState,
    app: Option<&AppHandle>,
) -> Result<RefreshOutcome, String> {
    let (kind, url, configured_format, category, stored_hash, etag, last_modified) = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        db.query_row(
            "SELECT kind,url,format,COALESCE(category,'custom'),content_sha256,http_etag,http_last_modified
             FROM subscriptions WHERE id=?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(|_| "订阅不存在")?
    };
    let downloaded = if kind == "rule" {
        match local_rule_source_path(&url) {
            Ok(Some(path)) => {
                emit_refresh_progress(app, &id, "downloading", 0, None, "正在读取本地规则");
                DownloadOutcome::Downloaded {
                    bytes: fs::read(&path).map_err(|value| {
                        format!("读取本地规则失败（{}）：{value}", path.display())
                    })?,
                    etag: None,
                    last_modified: None,
                }
            }
            Ok(None) => {
                download_subscription_bytes(
                    &url,
                    app,
                    &id,
                    etag.as_deref(),
                    last_modified.as_deref(),
                )
                .await?
            }
            Err(reason) => return record_error(state, &id, reason),
        }
    } else {
        download_subscription_bytes(&url, app, &id, etag.as_deref(), last_modified.as_deref())
            .await?
    };
    if matches!(downloaded, DownloadOutcome::NotModified) {
        mark_subscription_unchanged(state, &id, etag.as_deref(), last_modified.as_deref(), false)?;
        return Ok(RefreshOutcome {
            report: cached_refresh_report(state, &id, configured_format.as_deref())?,
            changed: false,
        });
    }
    let DownloadOutcome::Downloaded {
        bytes,
        etag: response_etag,
        last_modified: response_last_modified,
    } = downloaded
    else {
        unreachable!()
    };
    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return record_error(state, &id, "订阅文件超过20MB限制".into());
    }
    let content_hash = format!("{:x}", Sha256::digest(&bytes));
    if stored_hash.as_deref() == Some(content_hash.as_str()) {
        mark_subscription_unchanged(
            state,
            &id,
            response_etag.as_deref(),
            response_last_modified.as_deref(),
            true,
        )?;
        return Ok(RefreshOutcome {
            report: cached_refresh_report(state, &id, configured_format.as_deref())?,
            changed: false,
        });
    }
    let byte_len = bytes.len();
    let text = String::from_utf8(bytes).map_err(|_| "订阅不是有效UTF-8文本")?;
    emit_refresh_progress(
        app,
        &id,
        "importing",
        byte_len,
        Some(byte_len),
        "正在验证并写入规则",
    );

    let report = if kind == "rule" {
        refresh_rules(
            state,
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
    db.execute(
        "UPDATE subscriptions
            SET format=?1,last_updated_at=CURRENT_TIMESTAMP,last_error=NULL,
                content_sha256=?2,http_etag=?3,http_last_modified=?4
          WHERE id=?5",
        params![
            report.detected_format,
            content_hash,
            response_etag,
            response_last_modified,
            id
        ],
    )
    .map_err(error)?;
    drop(db);
    Ok(RefreshOutcome {
        report,
        changed: true,
    })
}

fn mark_subscription_unchanged(
    state: &AppState,
    id: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    replace_validators: bool,
) -> Result<(), String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    if replace_validators {
        db.execute(
            "UPDATE subscriptions
                SET last_updated_at=CURRENT_TIMESTAMP,last_error=NULL,
                    http_etag=?1,http_last_modified=?2
              WHERE id=?3",
            params![etag, last_modified, id],
        )
        .map_err(error)?;
    } else {
        db.execute(
            "UPDATE subscriptions
                SET last_updated_at=CURRENT_TIMESTAMP,last_error=NULL,
                    http_etag=COALESCE(?1,http_etag),
                    http_last_modified=COALESCE(?2,http_last_modified)
              WHERE id=?3",
            params![etag, last_modified, id],
        )
        .map_err(error)?;
    }
    Ok(())
}

fn cached_refresh_report(
    state: &AppState,
    id: &str,
    configured_format: Option<&str>,
) -> Result<RefreshReport, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let imported_count = db
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM imported_rules WHERE subscription_id=?1)
               + (SELECT COUNT(*) FROM safe_search_mappings WHERE subscription_id=?1)",
            params![id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(error)? as usize;
    Ok(RefreshReport {
        detected_format: configured_format.unwrap_or("auto").to_owned(),
        imported_count,
        ignored_count: 0,
        proxy_count: 0,
        group_count: 0,
        updated: false,
    })
}

fn local_rule_source_path(source: &str) -> Result<Option<PathBuf>, String> {
    let source = source.trim();
    if source.starts_with("http://") || source.starts_with("https://") {
        return Ok(None);
    }
    if source.starts_with("file://") {
        let url = url::Url::parse(source).map_err(|_| "本地规则 file URL 无效")?;
        return url
            .to_file_path()
            .map(Some)
            .map_err(|_| "本地规则 file URL 无法转换为文件路径".into());
    }
    if source.contains("://") {
        return Err("规则源必须是本地文件路径、file URL 或 HTTP(S) URL".into());
    }
    Ok(Some(PathBuf::from(source)))
}

async fn download_subscription_bytes(
    url: &str,
    app: Option<&AppHandle>,
    id: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<DownloadOutcome, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("clash-verge/v2.0")
        .build()
        .map_err(error)?;
    let mut request = client
        .get(url)
        .header(CACHE_CONTROL, "no-cache")
        .header(PRAGMA, "no-cache");
    if let Some(value) = etag {
        request = request.header(IF_NONE_MATCH, value);
    }
    if let Some(value) = last_modified {
        request = request.header(IF_MODIFIED_SINCE, value);
    }
    let response = request
        .send()
        .await
        .map_err(|value| format!("订阅下载失败：{value}"))?;
    if response.status() == StatusCode::NOT_MODIFIED {
        return Ok(DownloadOutcome::NotModified);
    }
    if !response.status().is_success() {
        return Err(format!("服务器返回 {}", response.status()));
    }
    let response_etag = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response_last_modified = response
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let total = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if total.is_some_and(|size| size > MAX_SUBSCRIPTION_BYTES) {
        return Err("订阅文件超过20MB限制".into());
    }
    emit_refresh_progress(app, id, "downloading", 0, total, "正在下载规则");
    Ok(DownloadOutcome::Downloaded {
        bytes: read_subscription_bytes(response, app, id).await?,
        etag: response_etag,
        last_modified: response_last_modified,
    })
}

async fn read_subscription_bytes(
    mut response: reqwest::Response,
    app: Option<&AppHandle>,
    id: &str,
) -> Result<Vec<u8>, String> {
    let total = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let mut bytes = Vec::with_capacity(total.unwrap_or_default().min(MAX_SUBSCRIPTION_BYTES));
    while let Some(chunk) = response.chunk().await.map_err(error)? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err("订阅文件超过20MB限制".into());
        }
        emit_refresh_progress(app, id, "downloading", bytes.len(), total, "正在下载规则");
    }
    Ok(bytes)
}

fn emit_refresh_progress(
    app: Option<&AppHandle>,
    id: &str,
    phase: &str,
    downloaded_bytes: usize,
    total_bytes: Option<usize>,
    message: &str,
) {
    let Some(app) = app else {
        return;
    };
    let percent = total_bytes
        .filter(|total| *total > 0)
        .map(|total| ((downloaded_bytes.saturating_mul(100) / total).min(100)) as u8);
    let _ = app.emit(
        SUBSCRIPTION_PROGRESS_EVENT,
        SubscriptionRefreshProgress {
            id: id.to_owned(),
            phase: phase.to_owned(),
            downloaded_bytes,
            total_bytes,
            percent,
            message: message.to_owned(),
        },
    );
}

#[tauri::command]
pub fn import_proxy_payload(
    input: ManualProxyImport,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionRecord, String> {
    state.require_session(&session_token)?;
    import_proxy_payload_inner(input, &state)
}

fn import_proxy_payload_inner(
    input: ManualProxyImport,
    state: &AppState,
) -> Result<SubscriptionRecord, String> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("代理名称无效".into());
    }
    let content = input.content.trim();
    if content.is_empty() {
        return Err("代理内容不能为空".into());
    }
    let (report, payload) = parse_proxy_payload(content)?;
    let id = Uuid::new_v4().to_string();
    let url = format!("manual://proxy/{id}");
    {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        db.execute("INSERT INTO subscriptions(id,kind,name,url,format,update_interval_hours,last_updated_at,last_error) VALUES(?1,'proxy',?2,?3,?4,NULL,CURRENT_TIMESTAMP,NULL)",params![id,name,url,report.detected_format]).map_err(error)?;
    }
    store_proxy_payload(state, &id, &report.detected_format, &payload)?;
    subscription_record(state, &id)
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

fn subscription_record(state: &AppState, id: &str) -> Result<SubscriptionRecord, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    db.query_row(
        "SELECT s.id, s.kind, s.name, s.url, s.format, s.category, s.update_interval_hours, s.enabled, s.last_updated_at, s.last_error,
         COALESCE((SELECT COUNT(*) FROM imported_rules r WHERE r.subscription_id=s.id),0)
           + COALESCE((SELECT COUNT(*) FROM safe_search_mappings m WHERE m.subscription_id=s.id),0) AS imported_rule_count,
         COALESCE((SELECT COUNT(*) FROM imported_rules r WHERE r.subscription_id=s.id
           AND s.enabled=1
           AND NOT (r.category='strict' AND COALESCE((SELECT value FROM settings WHERE key='strict_mode_enabled'),'false')!='true')
           AND COALESCE((SELECT value FROM settings WHERE key='category.' || r.category),'true')!='false'),0)
           + COALESCE((SELECT COUNT(*) FROM safe_search_mappings m WHERE m.subscription_id=s.id
             AND s.enabled=1
             AND COALESCE((SELECT value FROM settings WHERE key='safe_search_enabled'),'true')='true'),0) AS active_rule_count,
         s.ui_group, s.ui_order, s.toggleable, s.description
         FROM subscriptions s WHERE s.id=?1",
        params![id],
        |row| {
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
                imported_rule_count: row.get(10)?,
                active_rule_count: row.get(11)?,
                ui_group: row.get(12)?,
                ui_order: row.get(13)?,
                toggleable: row.get::<_, i64>(14)? != 0,
                description: row.get(15)?,
            })
        },
    )
    .map_err(error)
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
        if let Ok(outcome) = refresh_subscription_inner(id, &state, None).await {
            updated += usize::from(outcome.changed);
        }
    }
    Ok(updated)
}

#[tauri::command]
pub async fn refresh_builtin_rule_sources(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<RuleSourceRefreshReport, String> {
    state.require_session(&session_token)?;
    refresh_builtin_rule_sources_inner(&state).await
}

async fn refresh_builtin_rule_sources_inner(
    state: &AppState,
) -> Result<RuleSourceRefreshReport, String> {
    let source_ids = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        let mut statement = db
            .prepare(
                "SELECT id FROM subscriptions
                  WHERE kind='rule'
                    AND (id LIKE 'default:%' OR id LIKE 'local:cleanweb:%' OR url LIKE 'builtin://%')
                  ORDER BY COALESCE(ui_order,999999),created_at",
            )
            .map_err(error)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(error)?;
        ids
    };
    let checked_count = source_ids.len();
    let mut updated_count = 0;
    let mut unchanged_count = 0;
    let mut failed_count = 0;
    for id in source_ids {
        match refresh_subscription_inner(id, state, None).await {
            Ok(outcome) if outcome.changed => updated_count += 1,
            Ok(_) => unchanged_count += 1,
            Err(_) => failed_count += 1,
        }
    }
    Ok(RuleSourceRefreshReport {
        checked_count,
        updated_count,
        unchanged_count,
        failed_count,
    })
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
    if matches!(format, SubscriptionFormat::SafeSearch) {
        return refresh_safe_search_rules(state, id, text);
    }
    let imported = import_text(format, text, id, url, category);
    if imported.rules.is_empty() {
        return Err("规则文件没有可用条目，继续使用最后一次有效规则".into());
    }
    let mut db = state.db.lock().map_err(|_| "数据库不可用")?;
    let tx = db.transaction().map_err(error)?;
    tx.execute(
        "DELETE FROM imported_rules WHERE subscription_id=?1",
        params![id],
    )
    .map_err(error)?;
    tx.execute(
        "DELETE FROM safe_search_mappings WHERE subscription_id=?1",
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
        updated: true,
    })
}

fn refresh_safe_search_rules(
    state: &AppState,
    id: &str,
    text: &str,
) -> Result<RefreshReport, String> {
    let report = import_safe_search_mappings(text)?;
    if report.mappings.is_empty() {
        return Err("安全搜索规则没有可用映射，继续使用最后一次有效规则".into());
    }
    let mut db = state.db.lock().map_err(|_| "数据库不可用")?;
    let tx = db.transaction().map_err(error)?;
    tx.execute(
        "DELETE FROM imported_rules WHERE subscription_id=?1",
        params![id],
    )
    .map_err(error)?;
    tx.execute(
        "DELETE FROM safe_search_mappings WHERE subscription_id=?1",
        params![id],
    )
    .map_err(error)?;
    let imported_count = report.mappings.len();
    let ignored_count = report.ignored.len();
    for mapping in report.mappings {
        tx.execute(
            "INSERT INTO safe_search_mappings(subscription_id,domain,target,source_line)
             VALUES(?1,?2,?3,?4)",
            params![
                id,
                mapping.domain,
                mapping.target,
                mapping.source_line as i64
            ],
        )
        .map_err(error)?;
    }
    tx.commit().map_err(error)?;
    Ok(RefreshReport {
        detected_format: "safe-search".into(),
        imported_count,
        ignored_count,
        proxy_count: 0,
        group_count: 0,
        updated: true,
    })
}

fn parse_proxy_payload(text: &str) -> Result<(RefreshReport, String), String> {
    let imported = cleanweb_proxy_import::parse_proxy_payload(text)?;
    Ok((
        RefreshReport {
            detected_format: imported.report.detected_format,
            imported_count: 0,
            ignored_count: 0,
            proxy_count: imported.report.proxy_count,
            group_count: imported.report.group_count,
            updated: true,
        },
        imported.payload,
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
    if text.contains("mappings:") && lines.iter().any(|line| line.starts_with("target:")) {
        return SubscriptionFormat::SafeSearch;
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
    use base64::Engine;
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
    fn imports_safe_search_subscription_mappings() {
        let state = AppState::open(":memory:").unwrap();
        state.db.lock().unwrap().execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('safe','rule','safe','https://example.test/safe.yaml',1)",[]).unwrap();
        let report = refresh_rules(
            &state,
            "safe",
            "https://example.test/safe.yaml",
            Some("safe-search"),
            "custom",
            "version: 1\nmappings:\n  - domain: search.example.com\n    target: forcesafesearch.google.com\n",
        )
        .unwrap();
        assert_eq!(report.detected_format, "safe-search");
        assert_eq!(report.imported_count, 1);
        let mapping: (String, String) = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT domain,target FROM safe_search_mappings WHERE subscription_id='safe'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            mapping,
            (
                "search.example.com".into(),
                "forcesafesearch.google.com".into()
            )
        );
        let normal_rules: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM imported_rules WHERE subscription_id='safe'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(normal_rules, 0);
    }

    #[test]
    fn refreshed_rule_subscription_replaces_configured_fallback_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cleanweb.db");
        let source_id = "local:cleanweb:entertainment-short-video";
        {
            let state = AppState::open(&path).unwrap();
            let original_count: i64 = state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM imported_rules WHERE subscription_id=?1",
                    params![source_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(original_count > 2);

            let report = refresh_rules(
                &state,
                source_id,
                "https://example.test/short-video.clash",
                Some("clash"),
                "entertainment",
                "DOMAIN,replacement.example,DIRECT\nDOMAIN-SUFFIX,blocked.example,REJECT\n",
            )
            .unwrap();
            assert_eq!(report.imported_count, 2);
        }

        let state = AppState::open(&path).unwrap();
        let db = state.db.lock().unwrap();
        let rules = db
            .prepare(
                "SELECT pattern,action FROM imported_rules
                 WHERE subscription_id=?1 ORDER BY source_line",
            )
            .unwrap()
            .query_map(params![source_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rules,
            vec![
                ("replacement.example".into(), "Allow".into()),
                ("blocked.example".into(), "Block".into()),
            ]
        );
    }

    #[test]
    fn invalid_rule_refresh_preserves_last_valid_rules() {
        let state = AppState::open(":memory:").unwrap();
        let source_id = "local:cleanweb:entertainment-short-video";
        let before: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM imported_rules WHERE subscription_id=?1",
                params![source_id],
                |row| row.get(0),
            )
            .unwrap();

        let error = refresh_rules(
            &state,
            source_id,
            "https://example.test/short-video.clash",
            Some("clash"),
            "entertainment",
            "this is not a valid clash rule\n",
        )
        .unwrap_err();
        assert!(error.contains("最后一次有效规则"));

        let after: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM imported_rules WHERE subscription_id=?1",
                params![source_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn local_rule_source_is_cached_after_source_file_is_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("local-rules.clash");
        std::fs::write(&source_path, "DOMAIN-SUFFIX,cached-local.example,REJECT\n").unwrap();
        let state = AppState::open(directory.path().join("cleanweb.db")).unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO subscriptions(id,kind,name,url,format,category,enabled) VALUES('local-file','rule','Local file',?1,'clash','custom',1)",
                params![source_path.to_string_lossy()],
            )
            .unwrap();

        tauri::async_runtime::block_on(refresh_subscription_inner(
            "local-file".into(),
            &state,
            None,
        ))
        .unwrap();
        std::fs::remove_file(&source_path).unwrap();
        assert!(tauri::async_runtime::block_on(refresh_subscription_inner(
            "local-file".into(),
            &state,
            None,
        ))
        .is_err());

        let cached: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM imported_rules WHERE subscription_id='local-file' AND pattern='cached-local.example'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cached, 1, "源文件丢失后必须保留最后一次有效缓存");
    }

    #[test]
    fn manual_builtin_check_ignores_interval_and_detects_content_hash_changes() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("builtin-rules.clash");
        std::fs::write(&source_path, "DOMAIN-SUFFIX,first.example,REJECT\n").unwrap();
        let state = AppState::open(directory.path().join("cleanweb.db")).unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("DELETE FROM imported_rules", []).unwrap();
            db.execute("DELETE FROM safe_search_mappings", []).unwrap();
            db.execute("DELETE FROM subscriptions", []).unwrap();
            db.execute(
                "INSERT INTO subscriptions(
                   id,kind,name,url,format,category,update_interval_hours,enabled,last_updated_at
                 ) VALUES(
                   'default:test:forced','rule','Forced check',?1,'clash','custom',24,0,CURRENT_TIMESTAMP
                 )",
                params![source_path.to_string_lossy()],
            )
            .unwrap();
        }

        let first =
            tauri::async_runtime::block_on(refresh_builtin_rule_sources_inner(&state)).unwrap();
        assert_eq!(first.checked_count, 1);
        assert_eq!(first.updated_count, 1);
        assert_eq!(first.unchanged_count, 0);

        let unchanged =
            tauri::async_runtime::block_on(refresh_builtin_rule_sources_inner(&state)).unwrap();
        assert_eq!(unchanged.updated_count, 0);
        assert_eq!(unchanged.unchanged_count, 1);

        std::fs::write(&source_path, "DOMAIN-SUFFIX,second.example,REJECT\n").unwrap();
        let changed =
            tauri::async_runtime::block_on(refresh_builtin_rule_sources_inner(&state)).unwrap();
        assert_eq!(changed.updated_count, 1);
        let current_pattern: String = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT pattern FROM imported_rules WHERE subscription_id='default:test:forced'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_pattern, "second.example");
    }

    #[test]
    fn http_rule_check_uses_etag_and_accepts_not_modified() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains("cache-control: no-cache"));
                if request_index == 0 {
                    let body = "DOMAIN-SUFFIX,etag.example,REJECT\n";
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                } else {
                    assert!(request.contains("if-none-match: \"v1\""));
                    stream
                        .write_all(
                            b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                }
            }
        });

        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("DELETE FROM imported_rules", []).unwrap();
            db.execute("DELETE FROM safe_search_mappings", []).unwrap();
            db.execute("DELETE FROM subscriptions", []).unwrap();
            db.execute(
                "INSERT INTO subscriptions(
                   id,kind,name,url,format,category,update_interval_hours,enabled,last_updated_at
                 ) VALUES(
                   'default:test:http','rule','HTTP check',?1,'clash','custom',24,1,CURRENT_TIMESTAMP
                 )",
                params![format!("http://{address}/rules.clash")],
            )
            .unwrap();
        }

        let first =
            tauri::async_runtime::block_on(refresh_builtin_rule_sources_inner(&state)).unwrap();
        assert_eq!(first.updated_count, 1);
        let second =
            tauri::async_runtime::block_on(refresh_builtin_rule_sources_inner(&state)).unwrap();
        assert_eq!(second.updated_count, 0);
        assert_eq!(second.unchanged_count, 1);
        server.join().unwrap();
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
    fn imports_manual_proxy_payload_without_refresh_interval() {
        let _guard = test_key_env_lock();
        std::env::set_var(
            "CLEANWEB_TEST_PROXY_KEY_B64",
            base64::engine::general_purpose::STANDARD.encode([8_u8; 32]),
        );
        let state = AppState::open(":memory:").unwrap();
        let item = import_proxy_payload_inner(
            ManualProxyImport {
                name: "手动节点".into(),
                content: "ss://YWVzLTEyOC1nY206dGVzdA==@example.com:8388#my-ss".into(),
            },
            &state,
        )
        .unwrap();

        assert_eq!(item.kind, "proxy");
        assert_eq!(item.name, "手动节点");
        assert_eq!(item.update_interval_hours, None);
        assert!(item.url.starts_with("manual://proxy/"));
        let stored: String = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM proxy_payloads WHERE subscription_id=?1",
                params![item.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(is_encrypted_proxy_payload(&stored));
        assert!(decrypt_proxy_payload(&stored).unwrap().contains("my-ss"));
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }
}
