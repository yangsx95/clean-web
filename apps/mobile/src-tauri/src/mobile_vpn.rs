use serde::{Deserialize, Serialize};
#[cfg(target_os = "android")]
use serde_yaml::{Mapping, Value};
use tauri::plugin::TauriPlugin;

#[cfg(target_os = "android")]
use crate::mobile_subscription_store::{
    self, StoredProxyInfo, StoredSafeSearchMapping, StoredSubscriptionRule,
};
use crate::mobile_subscription_store::{StoredProxyGroup, StoredProxyNode};
#[cfg(target_os = "android")]
use cleanweb_proxy_import::parse_proxy_payload;
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
    pub data_plane_mode: String,
    pub last_error: Option<String>,
    pub last_policy_updated_at: Option<u64>,
    pub last_started_at: Option<u64>,
    pub last_dns_activity_at: Option<u64>,
    pub dns_query_count: u64,
    pub blocked_dns_query_count: u64,
    pub upstream_failure_count: u64,
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
pub struct MobileProxyImportPayload {
    pub id: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileRefreshReport {
    pub detected_format: String,
    pub imported_count: usize,
    pub ignored_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
    pub updated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSubscriptionProxyInfo {
    pub proxies: Vec<StoredProxyNode>,
    pub groups: Vec<StoredProxyGroup>,
    pub payload_ready: bool,
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
#[tauri::command]
pub async fn mobile_refresh_proxy_subscription(
    app: tauri::AppHandle,
    payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    let text = read_mobile_source(&payload.url, "代理订阅", 20 * 1024 * 1024).await?;
    import_mobile_proxy_payload(&app, &payload.id, &text)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_refresh_proxy_subscription(
    _payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    Err("Android proxy subscription refresh is only available in the Android mobile app".into())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_import_proxy_payload(
    app: tauri::AppHandle,
    payload: MobileProxyImportPayload,
) -> Result<MobileRefreshReport, String> {
    import_mobile_proxy_payload(&app, &payload.id, &payload.content)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_import_proxy_payload(
    _payload: MobileProxyImportPayload,
) -> Result<MobileRefreshReport, String> {
    Err("Android proxy import is only available in the Android mobile app".into())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_get_subscription_proxies(
    app: tauri::AppHandle,
    subscription_id: String,
) -> Result<MobileSubscriptionProxyInfo, String> {
    let info = mobile_subscription_store::read_proxy_info(
        &subscription_store_dir(&app)?,
        &subscription_id,
    )?;
    let payload_ready = mobile_subscription_store::read_proxy_payload(
        &subscription_store_dir(&app)?,
        &subscription_id,
    )?
    .is_some();
    Ok(MobileSubscriptionProxyInfo {
        proxies: info.proxies,
        groups: info.groups,
        payload_ready,
    })
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_get_subscription_proxies(
    _subscription_id: String,
) -> Result<MobileSubscriptionProxyInfo, String> {
    Err("Android proxy nodes are only available in the Android mobile app".into())
}

#[cfg(target_os = "android")]
fn policy_with_store_dir(app: &tauri::AppHandle, policy_json: &str) -> Result<String, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(policy_json).map_err(|error| error.to_string())?;
    let store_dir = subscription_store_dir(app)?;
    value["subscriptionStoreDir"] = serde_json::Value::String(store_dir.to_string_lossy().into());
    if mobile_proxy_enabled(&value) {
        let config_path = write_mobile_mihomo_config(app, &store_dir, &value)?;
        value["mihomoConfigPath"] =
            serde_json::Value::String(config_path.to_string_lossy().into_owned());
        value["mihomoEnabled"] = serde_json::Value::Bool(true);
    } else {
        value["mihomoEnabled"] = serde_json::Value::Bool(false);
    }
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
async fn refresh_mobile_subscription(
    app: &tauri::AppHandle,
    payload: MobileSubscriptionRefreshPayload,
) -> Result<MobileRefreshReport, String> {
    let text = read_mobile_source(&payload.url, "规则订阅", 20 * 1024 * 1024).await?;
    let format = subscription_format(payload.format.as_deref(), &text)?;
    let category = payload.category.as_deref().unwrap_or("custom");
    let store_dir = subscription_store_dir(app)?;
    if format == SubscriptionFormat::SafeSearch {
        let report = import_safe_search_mappings(&text)?;
        if report.mappings.is_empty() {
            return Err("安全搜索规则没有可用映射，继续使用最后一次有效缓存".into());
        }
        let updated = mobile_subscription_store::replace_safe_search_mappings(
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
            updated,
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
            item.rule.priority = mobile_rule_priority(item.rule.action, category);
            Some(StoredSubscriptionRule::from(item.rule))
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Err("规则文件没有可用条目，继续使用最后一次有效缓存".into());
    }
    let updated =
        mobile_subscription_store::replace_subscription_rules(&store_dir, &payload.id, rules)?;
    let imported_count =
        mobile_subscription_store::read_subscription_rules(&store_dir, &payload.id)?.len();
    Ok(MobileRefreshReport {
        detected_format: format_name(format).into(),
        imported_count,
        ignored_count,
        proxy_count: 0,
        group_count: 0,
        updated,
    })
}

#[cfg(target_os = "android")]
fn import_mobile_proxy_payload(
    app: &tauri::AppHandle,
    id: &str,
    text: &str,
) -> Result<MobileRefreshReport, String> {
    let imported = parse_proxy_payload(text)?;
    let info = proxy_info_from_payload(&imported.payload)?;
    if info.proxies.is_empty() {
        return Err("代理订阅没有可用节点".into());
    }
    let store_dir = subscription_store_dir(app)?;
    let payload_updated =
        mobile_subscription_store::replace_proxy_payload(&store_dir, id, &imported.payload)?;
    let info_updated = mobile_subscription_store::replace_proxy_info(&store_dir, id, &info)?;
    Ok(MobileRefreshReport {
        detected_format: imported.report.detected_format,
        imported_count: 0,
        ignored_count: 0,
        proxy_count: info.proxies.len(),
        group_count: info.groups.len(),
        updated: payload_updated || info_updated,
    })
}

#[cfg(target_os = "android")]
fn mobile_proxy_enabled(policy: &serde_json::Value) -> bool {
    policy
        .get("settings")
        .and_then(|settings| settings.get("proxyEnabled"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn write_mobile_mihomo_config(
    app: &tauri::AppHandle,
    store_dir: &std::path::Path,
    policy: &serde_json::Value,
) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;

    let runtime = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法获取 Android 应用数据目录：{error}"))?
        .join("mihomo");
    std::fs::create_dir_all(&runtime).map_err(|error| error.to_string())?;
    let config_path = runtime.join("config.yaml");
    let config = build_mobile_mihomo_config(store_dir, policy)?;
    std::fs::write(&config_path, config).map_err(|error| error.to_string())?;
    Ok(config_path)
}

#[cfg(target_os = "android")]
fn build_mobile_mihomo_config(
    store_dir: &std::path::Path,
    policy: &serde_json::Value,
) -> Result<String, String> {
    let enabled_proxy_ids = policy
        .get("subscriptions")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("kind").and_then(serde_json::Value::as_str) == Some("proxy")
                && item
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
        })
        .filter_map(|item| item.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    if enabled_proxy_ids.is_empty() {
        return Err("已开启网络代理，但没有启用的代理订阅；请先导入并启用代理订阅".into());
    }
    let mut proxies = Vec::new();
    let mut groups = Vec::new();
    for id in enabled_proxy_ids {
        let Some(payload) = mobile_subscription_store::read_proxy_payload(store_dir, id)? else {
            let info = mobile_subscription_store::read_proxy_info(store_dir, id)?;
            if !info.proxies.is_empty() {
                return Err(format!(
                    "代理订阅缓存不完整（{id}）：节点摘要存在，但 Android 代理配置缺失；请刷新该代理订阅或重新导入"
                ));
            }
            continue;
        };
        let value: Value = serde_yaml::from_str(&payload).map_err(|error| error.to_string())?;
        if let Some(items) = value.get("proxies").and_then(Value::as_sequence) {
            proxies.extend(items.iter().cloned());
        }
        if let Some(items) = value.get("proxy-groups").and_then(Value::as_sequence) {
            groups.extend(items.iter().cloned());
        }
    }
    deduplicate_named(&mut proxies);
    deduplicate_named(&mut groups);
    let proxy_names = proxies
        .iter()
        .filter_map(|value| {
            value
                .get("name")
                .and_then(Value::as_str)
                .map(|name| Value::String(name.into()))
        })
        .collect::<Vec<_>>();
    let mut proxy_names = proxy_names;
    if proxy_names.is_empty() {
        return Err("已开启网络代理，但 Android 没有可用代理节点；请重新导入代理订阅".into());
    }
    if let Some(selected) = policy
        .get("proxySelection")
        .and_then(serde_json::Value::as_str)
    {
        move_named_first(&mut proxy_names, selected);
    }
    sanitize_mobile_proxy_groups(&mut groups, &proxy_names);

    let mut root = Mapping::new();
    insert_yaml(&mut root, "allow-lan", Value::Bool(false));
    insert_yaml(&mut root, "mode", Value::String("rule".into()));
    insert_yaml(&mut root, "log-level", Value::String("info".into()));
    insert_yaml(&mut root, "ipv6", Value::Bool(true));
    insert_yaml(&mut root, "unified-delay", Value::Bool(true));
    insert_yaml(&mut root, "tcp-concurrent", Value::Bool(true));
    insert_yaml(
        &mut root,
        "external-controller",
        Value::String("127.0.0.1:19090".into()),
    );
    insert_yaml(&mut root, "secret", Value::String("cleanweb-mobile".into()));

    let mut dns = Mapping::new();
    insert_yaml(&mut dns, "enable", Value::Bool(true));
    insert_yaml(&mut dns, "listen", Value::String("127.0.0.1:1053".into()));
    insert_yaml(
        &mut dns,
        "enhanced-mode",
        Value::String("redir-host".into()),
    );
    insert_yaml(
        &mut dns,
        "nameserver",
        Value::Sequence(vec![
            Value::String("1.1.1.1".into()),
            Value::String("8.8.8.8".into()),
        ]),
    );
    insert_yaml(&mut root, "dns", Value::Mapping(dns));

    let mut tun = Mapping::new();
    insert_yaml(&mut tun, "enable", Value::Bool(true));
    insert_yaml(&mut tun, "stack", Value::String("gvisor".into()));
    insert_yaml(&mut tun, "auto-route", Value::Bool(false));
    insert_yaml(&mut tun, "auto-detect-interface", Value::Bool(false));
    insert_yaml(&mut tun, "file-descriptor", Value::Number(3.into()));
    insert_yaml(
        &mut tun,
        "dns-hijack",
        Value::Sequence(vec![Value::String("any:53".into())]),
    );
    insert_yaml(
        &mut tun,
        "route-exclude-address",
        Value::Sequence(vec![
            Value::String("127.0.0.0/8".into()),
            Value::String("::1/128".into()),
        ]),
    );
    insert_yaml(&mut root, "tun", Value::Mapping(tun));

    insert_yaml(&mut root, "proxies", Value::Sequence(proxies));
    let mut cleanweb_group = Mapping::new();
    insert_yaml(
        &mut cleanweb_group,
        "name",
        Value::String("CleanWeb".into()),
    );
    insert_yaml(&mut cleanweb_group, "type", Value::String("select".into()));
    insert_yaml(&mut cleanweb_group, "proxies", Value::Sequence(proxy_names));
    groups.push(Value::Mapping(cleanweb_group));
    insert_yaml(&mut root, "proxy-groups", Value::Sequence(groups));
    insert_yaml(
        &mut root,
        "rules",
        Value::Sequence(vec![Value::String("MATCH,CleanWeb".into())]),
    );
    serde_yaml::to_string(&root).map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
fn deduplicate_named(values: &mut Vec<Value>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| {
        value
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| seen.insert(name.to_owned()))
    });
}

#[cfg(target_os = "android")]
fn move_named_first(values: &mut Vec<Value>, selected: &str) {
    if let Some(index) = values
        .iter()
        .position(|value| value.as_str() == Some(selected))
    {
        let value = values.remove(index);
        values.insert(0, value);
    }
}

#[cfg(target_os = "android")]
fn sanitize_mobile_proxy_groups(groups: &mut Vec<Value>, proxy_names: &[Value]) {
    let available = proxy_names
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::HashSet<_>>();
    groups.retain_mut(|group| {
        let Some(mapping) = group.as_mapping_mut() else {
            return false;
        };
        let Some(members) = mapping
            .get_mut(Value::String("proxies".into()))
            .and_then(Value::as_sequence_mut)
        else {
            return false;
        };
        members.retain(|member| member.as_str().is_some_and(|name| available.contains(name)));
        !members.is_empty()
    });
}

#[cfg(target_os = "android")]
fn insert_yaml(map: &mut Mapping, key: &str, value: Value) {
    map.insert(Value::String(key.into()), value);
}

#[cfg(target_os = "android")]
fn proxy_info_from_payload(payload: &str) -> Result<StoredProxyInfo, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(payload).map_err(|error| error.to_string())?;
    let proxies = value
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let node_type = item
                        .get("type")
                        .and_then(serde_yaml::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some(StoredProxyNode {
                        name: name.to_string(),
                        node_type,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let groups = value
        .get("proxy-groups")
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let members = item
                        .get("proxies")
                        .and_then(serde_yaml::Value::as_sequence)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|value| value.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let group_type = item
                        .get("type")
                        .and_then(serde_yaml::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some(StoredProxyGroup {
                        name: name.to_string(),
                        group_type,
                        members,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(StoredProxyInfo { proxies, groups })
}

#[cfg(target_os = "android")]
fn mobile_rule_priority(action: Action, category: &str) -> u16 {
    if matches!(category, "fraud" | "phishing" | "malware") && action == Action::Block {
        10
    } else if action == Action::Block {
        50
    } else if action == Action::Allow {
        70
    } else {
        80
    }
}

#[cfg(target_os = "android")]
async fn read_mobile_source(source: &str, label: &str, max_bytes: usize) -> Result<String, String> {
    let source = source.trim();
    let bytes = if source.starts_with("http://") || source.starts_with("https://") {
        let response = reqwest::get(source)
            .await
            .map_err(|error| format!("下载{label}失败：{error}"))?
            .error_for_status()
            .map_err(|error| format!("下载{label}失败：{error}"))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|error| format!("读取{label}失败：{error}"))?;
        if bytes.len() > max_bytes {
            return Err(format!("{label}超过{}MB限制", max_bytes / 1024 / 1024));
        }
        bytes.to_vec()
    } else {
        let path = if source.starts_with("file://") {
            reqwest::Url::parse(source)
                .map_err(|_| "本地规则 file URL 无效")?
                .to_file_path()
                .map_err(|_| "本地规则 file URL 无法转换为文件路径")?
        } else if source.contains("://") {
            return Err(format!(
                "{label}必须是本地文件路径、file URL 或 HTTP(S) URL"
            ));
        } else {
            std::path::PathBuf::from(source)
        };
        let metadata = std::fs::metadata(&path)
            .map_err(|error| format!("读取本地{label}失败（{}）：{error}", path.display()))?;
        if metadata.len() > max_bytes as u64 {
            return Err(format!("{label}超过{}MB限制", max_bytes / 1024 / 1024));
        }
        std::fs::read(&path)
            .map_err(|error| format!("读取本地{label}失败（{}）：{error}", path.display()))?
    };
    String::from_utf8(bytes).map_err(|_| format!("{label}不是有效UTF-8文本"))
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
        data_plane_mode: "unsupported".into(),
        last_error: Some("Android VPN is only available in the Android mobile app".into()),
        last_policy_updated_at: None,
        last_started_at: None,
        last_dns_activity_at: None,
        dns_query_count: 0,
        blocked_dns_query_count: 0,
        upstream_failure_count: 0,
    }
}
