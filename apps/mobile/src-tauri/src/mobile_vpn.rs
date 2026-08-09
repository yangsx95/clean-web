use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;

#[cfg(target_os = "android")]
use crate::mobile_subscription_store::{self, StoredSafeSearchMapping, StoredSubscriptionRule};
#[cfg(target_os = "android")]
use cleanweb_rules::{Action, MatcherKind};
#[cfg(target_os = "android")]
use cleanweb_subscriptions::{import_safe_search_mappings, import_text, SubscriptionFormat};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileVpnStatus {
    pub supported: bool,
    pub prepared: bool,
    pub running: bool,
    pub stage: String,
    pub data_plane_ready: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobilePolicyPayload {
    pub policy_json: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSubscriptionRefreshPayload {
    pub id: String,
    pub url: String,
    pub format: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileRefreshReport {
    pub detected_format: String,
    pub imported_count: usize,
    pub ignored_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
}

#[cfg(target_os = "android")]
pub fn init() -> TauriPlugin<tauri::Wry> {
    use tauri::{plugin::Builder, Manager};

    Builder::new("cleanwebVpn")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.cleanweb.mobile", "CleanWebVpnPlugin")?;
            app.manage(AndroidVpnPlugin(handle));
            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "android"))]
pub fn init() -> TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("cleanwebVpn").build()
}

#[cfg(target_os = "android")]
pub(crate) struct AndroidVpnPlugin(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
fn plugin_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_prepare_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("prepareVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_prepare_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_start_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("startVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_start_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_stop_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("stopVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_stop_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_vpn_status(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("vpnStatus", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_vpn_status() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_update_policy(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
    app: tauri::AppHandle,
    payload: MobilePolicyPayload,
) -> Result<MobileVpnStatus, String> {
    let payload = MobilePolicyPayload {
        policy_json: policy_with_store_dir(&app, &payload.policy_json)?,
    };
    plugin
        .0
        .run_mobile_plugin_async("updatePolicy", payload)
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_update_policy(
    _payload: MobilePolicyPayload,
) -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_refresh_subscription(
    app: tauri::AppHandle,
    payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    refresh_mobile_subscription(&app, payload).await
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_refresh_subscription(
    _payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    Err("Android subscription refresh is only available in the Android mobile app".into())
}

#[cfg(target_os = "android")]
fn policy_with_store_dir(app: &tauri::AppHandle, policy_json: &str) -> Result<String, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(policy_json).map_err(|error| error.to_string())?;
    let store_dir = subscription_store_dir(app)?;
    value["subscriptionStoreDir"] = serde_json::Value::String(store_dir.to_string_lossy().into());
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
async fn refresh_mobile_subscription(
    app: &tauri::AppHandle,
    payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    let text = read_mobile_rule_source(&payload.url).await?;
    let format = subscription_format(payload.format.as_deref(), &text)?;
    let category = payload.category.as_deref().unwrap_or("custom");
    let store_dir = subscription_store_dir(app)?;
    if format == SubscriptionFormat::SafeSearch {
        let report = import_safe_search_mappings(&text)?;
        if report.mappings.is_empty() {
            return Err("安全搜索规则没有可用映射，继续使用最后一次有效缓存".into());
        }
        mobile_subscription_store::write_safe_search_mappings(
            &store_dir,
            &payload.id,
            report
                .mappings
                .into_iter()
                .map(StoredSafeSearchMapping::from),
        )?;
        return Ok(MobileRefreshReport {
            detected_format: "safe-search".into(),
            imported_count: mobile_subscription_store::read_safe_search_mappings(
                &store_dir,
                &payload.id,
            )?
            .len(),
            ignored_count: report.ignored.len(),
            proxy_count: 0,
            group_count: 0,
        });
    }
    let imported = import_text(format, &text, &payload.id, &payload.url, category);
    let ignored_count = imported.ignored.len();
    let rules = imported
        .rules
        .into_iter()
        .filter_map(|mut item| {
            if !matches!(
                item.rule.kind,
                MatcherKind::Exact
                    | MatcherKind::Suffix
                    | MatcherKind::Contains
                    | MatcherKind::Wildcard
                    | MatcherKind::Regex
                    | MatcherKind::Ip
                    | MatcherKind::Cidr
            ) {
                return None;
            }
            if !matches!(item.rule.action, Action::Block | Action::Allow) {
                return None;
            }
            item.rule.priority = if matches!(item.rule.action, Action::Allow) {
                30
            } else {
                70
            };
            Some(StoredSubscriptionRule::from(item.rule))
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Err("规则文件没有可用条目，继续使用最后一次有效缓存".into());
    }
    mobile_subscription_store::write_subscription_rules(&store_dir, &payload.id, rules)?;
    let imported_count =
        mobile_subscription_store::read_subscription_rules(&store_dir, &payload.id)?.len();
    Ok(MobileRefreshReport {
        detected_format: format_name(format).into(),
        imported_count,
        ignored_count,
        proxy_count: 0,
        group_count: 0,
    })
}

#[cfg(target_os = "android")]
async fn read_mobile_rule_source(source: &str) -> Result<String, String> {
    const MAX_RULE_SOURCE_BYTES: usize = 20 * 1024 * 1024;
    let source = source.trim();
    let bytes = if source.starts_with("http://") || source.starts_with("https://") {
        let response = reqwest::get(source)
            .await
            .map_err(|error| format!("下载规则订阅失败：{error}"))?
            .error_for_status()
            .map_err(|error| format!("下载规则订阅失败：{error}"))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|error| format!("读取规则订阅失败：{error}"))?;
        if bytes.len() > MAX_RULE_SOURCE_BYTES {
            return Err("规则文件超过20MB限制".into());
        }
        bytes.to_vec()
    } else {
        let path = if source.starts_with("file://") {
            reqwest::Url::parse(source)
                .map_err(|_| "本地规则 file URL 无效")?
                .to_file_path()
                .map_err(|_| "本地规则 file URL 无法转换为文件路径")?
        } else if source.contains("://") {
            return Err("规则源必须是本地文件路径、file URL 或 HTTP(S) URL".into());
        } else {
            std::path::PathBuf::from(source)
        };
        let metadata = std::fs::metadata(&path)
            .map_err(|error| format!("读取本地规则失败（{}）：{error}", path.display()))?;
        if metadata.len() > MAX_RULE_SOURCE_BYTES as u64 {
            return Err("规则文件超过20MB限制".into());
        }
        std::fs::read(&path)
            .map_err(|error| format!("读取本地规则失败（{}）：{error}", path.display()))?
    };
    String::from_utf8(bytes).map_err(|_| "规则文件不是有效UTF-8文本".into())
}

#[cfg(target_os = "android")]
fn subscription_store_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法获取 Android 应用数据目录：{error}"))?;
    Ok(mobile_subscription_store::subscription_store_dir(
        &app_data_dir,
    ))
}

#[cfg(target_os = "android")]
fn subscription_format(value: Option<&str>, text: &str) -> Result<SubscriptionFormat, String> {
    match value.unwrap_or("auto") {
        "auto" => Ok(detect_rule_format(text)),
        "clash" => Ok(SubscriptionFormat::Clash),
        "hosts" => Ok(SubscriptionFormat::Hosts),
        "domain-list" => Ok(SubscriptionFormat::DomainList),
        "ip-list" => Ok(SubscriptionFormat::IpList),
        "adblock" => Ok(SubscriptionFormat::Adblock),
        "safe-search" => Ok(SubscriptionFormat::SafeSearch),
        other => Err(format!("不支持的规则订阅格式：{other}")),
    }
}

#[cfg(target_os = "android")]
fn detect_rule_format(text: &str) -> SubscriptionFormat {
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .take(30)
        .collect();
    if text.contains("mappings:") && lines.iter().any(|line| line.starts_with("target:")) {
        return SubscriptionFormat::SafeSearch;
    }
    if lines
        .iter()
        .any(|line| line.starts_with("||") || line.starts_with("@@||"))
    {
        return SubscriptionFormat::Adblock;
    }
    if lines.iter().any(|line| {
        line.split_whitespace().count() >= 2
            && line
                .split_whitespace()
                .next()
                .is_some_and(|value| value.parse::<std::net::IpAddr>().is_ok())
    }) {
        return SubscriptionFormat::Hosts;
    }
    if lines
        .iter()
        .any(|line| line.contains(',') || line.starts_with('-'))
    {
        return SubscriptionFormat::Clash;
    }
    if lines.iter().all(|line| {
        line.parse::<std::net::IpAddr>().is_ok() || line.parse::<ipnet::IpNet>().is_ok()
    }) {
        return SubscriptionFormat::IpList;
    }
    SubscriptionFormat::DomainList
}

#[cfg(target_os = "android")]
fn format_name(format: SubscriptionFormat) -> &'static str {
    match format {
        SubscriptionFormat::Clash => "clash",
        SubscriptionFormat::Hosts => "hosts",
        SubscriptionFormat::DomainList => "domain-list",
        SubscriptionFormat::IpList => "ip-list",
        SubscriptionFormat::Adblock => "adblock",
        SubscriptionFormat::SafeSearch => "safe-search",
    }
}

#[cfg(not(target_os = "android"))]
fn unsupported_status() -> MobileVpnStatus {
    MobileVpnStatus {
        supported: false,
        prepared: false,
        running: false,
        stage: "unsupported".into(),
        data_plane_ready: false,
        last_error: Some("Android VPN is only available in the Android mobile app".into()),
    }
}
