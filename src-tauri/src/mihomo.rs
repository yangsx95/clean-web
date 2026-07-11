use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use flate2::read::GzDecoder;
use reqwest::Url;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use crate::{
    platform::{self, NetworkConflicts},
    proxy_crypto::decrypt_proxy_payload,
    storage::AppState,
};

#[cfg(target_os = "macos")]
const ARM_GZ: &str = "mihomo-darwin-arm64-v1.19.28.gz";
#[cfg(target_os = "macos")]
const X64_GZ: &str = "mihomo-darwin-amd64-compatible-v1.19.28.gz";
#[cfg(target_os = "macos")]
const ARM_SHA256: &str = "40cdae2fab4b18df15f40eaa9dc3af70ab3d8be7f77164ae1e5f1af3a2a4fb44";
#[cfg(target_os = "macos")]
const X64_SHA256: &str = "a469cc2f6800e71b50eca3f74bc72a8f6f7e990a5d4aaecb81a68cf331516d9d";

#[cfg(target_os = "windows")]
const X64_GZ: &str = "mihomo-windows-amd64-v1.19.28.gz";
#[cfg(target_os = "windows")]
const X64_SHA256: &str = "16c476b5b80f3b6b120d2bb49f8b79626a5ad7f79c2898dac848f2730bc24944";
#[cfg(target_os = "windows")]
const ARM_GZ: &str = "";
#[cfg(target_os = "windows")]
const ARM_SHA256: &str = "";
const CONTROLLER: &str = "127.0.0.1:19090";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub controller: String,
    pub config_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelayResult {
    pub delay: u64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxyNode {
    pub name: String,
    pub node_type: String,
    pub delay: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxyGroup {
    pub name: String,
    pub group_type: String,
    pub now: String,
    pub nodes: Vec<ProxyNode>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProxyNode {
    pub name: String,
    pub node_type: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProxyGroup {
    pub name: String,
    pub group_type: String,
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProxyInfo {
    pub proxies: Vec<SubscriptionProxyNode>,
    pub groups: Vec<SubscriptionProxyGroup>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxyDelayResult {
    pub delays: std::collections::HashMap<String, u64>,
}

#[tauri::command]
pub fn get_network_conflicts() -> NetworkConflicts {
    platform::detect_network_conflicts()
}

#[tauri::command]
pub fn get_core_status(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    let mut process = state.core_process.lock().map_err(|_| "内核状态不可用")?;
    let mut running = match process.as_mut() {
        Some(child) => match child.try_wait().map_err(error)? {
            None => true,
            Some(_) => {
                *process = None;
                false
            }
        },
        None => false,
    };
    let mut pid = process.as_ref().map(|child| child.id());
    if !running {
        if let Some(saved) = read_pid(&state.data_dir.join("mihomo/mihomo.pid")) {
            if platform::pid_running(saved) {
                running = true;
                pid = Some(saved);
            }
        }
    }
    Ok(CoreStatus {
        running,
        pid,
        controller: CONTROLLER.into(),
        config_path: state
            .data_dir
            .join("mihomo/config.yaml")
            .display()
            .to_string(),
    })
}

#[tauri::command]
pub fn start_protection(
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    state.require_session(&session_token)?;
    start_inner(&app, &state)
}

#[tauri::command]
pub fn auto_start_protection(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    let protection_enabled = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        setting_bool(&db, "protection_enabled")?
    };
    if !protection_enabled {
        return get_core_status(state);
    }
    start_inner(&app, &state)
}

fn start_inner(app: &AppHandle, state: &AppState) -> Result<CoreStatus, String> {
    stop_child(&state)?;
    std::thread::sleep(Duration::from_millis(250));
    let conflicts = platform::detect_network_conflicts();
    if conflicts.has_conflict {
        return Err(format!(
            "检测到其他 VPN/TUN，CleanWeb 未启动：{}",
            conflicts
                .interfaces
                .into_iter()
                .chain(conflicts.vpn_services)
                .collect::<Vec<_>>()
                .join("、")
        ));
    }
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(app, &runtime)?;
    let secret = controller_secret(&state)?;
    let config = build_config(&state, &secret, true)?;
    atomic_write(&runtime.join("config.yaml"), config.as_bytes()).map_err(error)?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime.join("mihomo.log"))
        .map_err(error)?;
    let stderr = stdout.try_clone().map_err(error)?;
    let child = Command::new(binary)
        .arg("-d")
        .arg(&runtime)
        .arg("-f")
        .arg(runtime.join("config.yaml"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|value| format!("无法启动 Mihomo：{value}"))?;
    let pid = child.id();
    fs::write(runtime.join("mihomo.pid"), pid.to_string()).map_err(error)?;
    *state.core_process.lock().map_err(|_| "内核状态不可用")? = Some(child);
    std::thread::sleep(Duration::from_millis(650));
    let status = core_status(state)?;
    if !status.running {
        return Err(last_log_lines(&runtime.join("mihomo.log"), 12)
            .unwrap_or_else(|_| "Mihomo 启动后立即退出".into()));
    }
    Ok(status)
}

#[tauri::command]
pub fn stop_protection(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    state.require_session(&session_token)?;
    stop_child(&state)?;
    core_status(&state)
}

#[tauri::command]
pub async fn test_proxy_group(
    group: String,
    state: State<'_, AppState>,
) -> Result<DelayResult, String> {
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/group/")).map_err(error)?;
    url.path_segments_mut()
        .map_err(|_| "控制器地址无效")?
        .push(&group)
        .push("delay");
    url.query_pairs_mut()
        .append_pair("url", "https://www.gstatic.com/generate_204")
        .append_pair("timeout", "5000");
    let value = reqwest::Client::new()
        .get(url)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(error)?
        .error_for_status()
        .map_err(error)?
        .json::<serde_json::Value>()
        .await
        .map_err(error)?;
    let delay = value
        .get("delay")
        .and_then(|value| value.as_u64())
        .ok_or("测速响应无效")?;
    Ok(DelayResult { delay })
}

#[tauri::command]
pub async fn get_proxies(state: State<'_, AppState>) -> Result<Vec<ProxyGroup>, String> {
    let secret = controller_secret(&state)?;
    let url = format!("http://{CONTROLLER}/proxies");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&secret)
        .send()
        .await
        .map_err(error)?
        .error_for_status()
        .map_err(error)?
        .json::<serde_json::Value>()
        .await
        .map_err(error)?;
    let proxies = resp
        .get("proxies")
        .and_then(|v| v.as_object())
        .ok_or("代理响应无效")?;
    let mut groups = Vec::new();
    for (name, info) in proxies {
        let ptype = info.get("type").and_then(|v| v.as_str()).unwrap_or("");
        // 只显示代理组（Selector、URLTest、Fallback、LoadBalance 等）
        if !matches!(ptype, "Selector" | "URLTest" | "Fallback" | "LoadBalance") {
            continue;
        }
        let now = info.get("now").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let all = info.get("all").and_then(|v| v.as_array());
        let mut nodes = Vec::new();
        if let Some(all) = all {
            for item in all {
                let node_name = item.as_str().unwrap_or("");
                if node_name.is_empty() {
                    continue;
                }
                let node_info = proxies.get(node_name);
                let node_type = node_info
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let delay = node_info
                    .and_then(|v| v.get("history"))
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.last())
                    .and_then(|v| v.get("delay"))
                    .and_then(|v| v.as_u64());
                nodes.push(ProxyNode {
                    name: node_name.to_string(),
                    node_type,
                    delay,
                });
            }
        }
        groups.push(ProxyGroup {
            name: name.clone(),
            group_type: ptype.to_string(),
            now,
            nodes,
        });
    }
    Ok(groups)
}

#[tauri::command]
pub fn get_subscription_proxies(
    subscription_id: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionProxyInfo, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let envelope = db
        .query_row(
            "SELECT payload FROM proxy_payloads WHERE subscription_id=?1",
            params![subscription_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(error)?
        .ok_or_else(|| "该订阅尚未导入代理数据".to_string())?;
    drop(db);
    let plaintext = decrypt_proxy_payload(&envelope)?;
    let value: Value = serde_yaml::from_str(&plaintext).map_err(error)?;
    let mut proxies = Vec::new();
    if let Some(list) = value.get("proxies").and_then(Value::as_sequence) {
        for item in list {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let node_type = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            proxies.push(SubscriptionProxyNode { name, node_type });
        }
    }
    let mut groups = Vec::new();
    if let Some(list) = value.get("proxy-groups").and_then(Value::as_sequence) {
        for item in list {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let group_type = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let members = item
                .get("proxies")
                .and_then(Value::as_sequence)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            groups.push(SubscriptionProxyGroup {
                name,
                group_type,
                members,
            });
        }
    }
    Ok(SubscriptionProxyInfo { proxies, groups })
}

#[tauri::command]
pub async fn select_proxy(
    group: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/proxies/")).map_err(error)?;
    url.path_segments_mut()
        .map_err(|_| "代理组名称无效")?
        .push(&group);
    reqwest::Client::new()
        .put(url)
        .bearer_auth(&secret)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .map_err(error)?
        .error_for_status()
        .map_err(error)?;
    Ok(())
}

/// 测试指定代理组中所有节点的延迟，返回每个节点的延迟值
#[tauri::command]
pub async fn test_all_proxy_delays(
    group: String,
    state: State<'_, AppState>,
) -> Result<ProxyDelayResult, String> {
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/group/")).map_err(error)?;
    url.path_segments_mut()
        .map_err(|_| "控制器地址无效")?
        .push(&group)
        .push("delay");
    url.query_pairs_mut()
        .append_pair("url", "https://www.gstatic.com/generate_204")
        .append_pair("timeout", "5000");
    let resp = reqwest::Client::new()
        .get(url)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(error)?
        .error_for_status()
        .map_err(error)?
        .json::<serde_json::Value>()
        .await
        .map_err(error)?;
    let mut delays = std::collections::HashMap::new();
    if let Some(obj) = resp.as_object() {
        for (name, value) in obj {
            if let Some(delay) = value.as_u64() {
                delays.insert(name.clone(), delay);
            }
        }
    }
    Ok(ProxyDelayResult { delays })
}

fn stop_child(state: &AppState) -> Result<(), String> {
    let pid_path = state.data_dir.join("mihomo/mihomo.pid");
    if let Some(mut child) = state
        .core_process
        .lock()
        .map_err(|_| "内核状态不可用")?
        .take()
    {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(pid) = read_pid(&pid_path) {
        if platform::pid_running(pid) {
            platform::terminate_process(pid);
            for _ in 0..20 {
                if !platform::pid_running(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if platform::pid_running(pid) {
                platform::kill_process(pid);
            }
        }
    }
    let _ = fs::remove_file(pid_path);
    Ok(())
}

fn core_status(state: &AppState) -> Result<CoreStatus, String> {
    let pid = read_pid(&state.data_dir.join("mihomo/mihomo.pid"))
        .filter(|pid| platform::pid_running(*pid));
    Ok(CoreStatus {
        running: pid.is_some(),
        pid,
        controller: CONTROLLER.into(),
        config_path: state
            .data_dir
            .join("mihomo/config.yaml")
            .display()
            .to_string(),
    })
}
fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn build_config(state: &AppState, secret: &str, tun_enabled: bool) -> Result<String, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let proxy_enabled = setting_bool(&db, "proxy_enabled")?;
    let safe_search_enabled = setting_bool(&db, "safe_search_enabled")?;
    let mut proxies = Vec::new();
    let mut imported_groups = Vec::new();
    let mut statement = db.prepare("SELECT pp.format,pp.payload FROM proxy_payloads pp JOIN subscriptions s ON s.id=pp.subscription_id WHERE s.enabled=1 AND s.kind='proxy' ORDER BY s.created_at").map_err(error)?;
    let payloads = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    for (format, envelope) in payloads {
        let plaintext = decrypt_proxy_payload(&envelope)?;
        if format != "clash" {
            continue;
        }
        let value: Value = serde_yaml::from_str(&plaintext).map_err(error)?;
        if let Some(values) = value.get("proxies").and_then(Value::as_sequence) {
            proxies.extend(values.iter().cloned());
        }
        if let Some(values) = value.get("proxy-groups").and_then(Value::as_sequence) {
            imported_groups.extend(values.iter().cloned());
        }
    }
    deduplicate_named(&mut proxies);
    deduplicate_named(&mut imported_groups);
    let proxy_names: Vec<Value> = proxies
        .iter()
        .filter_map(|value| {
            value
                .get("name")
                .and_then(Value::as_str)
                .map(|name| Value::String(name.into()))
        })
        .collect();

    let mut root = Mapping::new();
    insert(&mut root, "mixed-port", Value::Number(7890.into()));
    insert(&mut root, "allow-lan", Value::Bool(false));
    insert(&mut root, "mode", Value::String("rule".into()));
    insert(&mut root, "log-level", Value::String("info".into()));
    insert(&mut root, "ipv6", Value::Bool(true));
    insert(
        &mut root,
        "external-controller",
        Value::String(CONTROLLER.into()),
    );
    insert(&mut root, "secret", Value::String(secret.into()));

    let mut tun = Mapping::new();
    insert(&mut tun, "enable", Value::Bool(tun_enabled));
    insert(&mut tun, "stack", Value::String("mixed".into()));
    insert(&mut tun, "device", Value::String("CleanWeb".into()));
    insert(&mut tun, "auto-route", Value::Bool(true));
    insert(&mut tun, "auto-detect-interface", Value::Bool(true));
    insert(
        &mut tun,
        "dns-hijack",
        Value::Sequence(vec![
            Value::String("any:53".into()),
            Value::String("tcp://any:53".into()),
        ]),
    );
    insert(&mut root, "tun", Value::Mapping(tun));

    let mut dns = Mapping::new();
    insert(&mut dns, "enable", Value::Bool(true));
    insert(&mut dns, "enhanced-mode", Value::String("fake-ip".into()));
    insert(
        &mut dns,
        "fake-ip-range",
        Value::String("198.18.0.1/16".into()),
    );
    insert(&mut dns, "use-hosts", Value::Bool(true));
    insert(&mut dns, "use-system-hosts", Value::Bool(true));
    insert(
        &mut dns,
        "nameserver",
        Value::Sequence(vec![
            Value::String("https://1.1.1.1/dns-query".into()),
            Value::String("https://8.8.8.8/dns-query".into()),
            Value::String("system://".into()),
        ]),
    );
    // 本地域名使用系统 DNS 解析，避免 fake-ip 导致无法访问路由器等内网设备
    let mut ns_policy = Mapping::new();
    insert(
        &mut ns_policy,
        "+.home,+.local,+.lan,+.internal,+.arpa",
        Value::Sequence(vec![
            Value::String("system://".into()),
            Value::String("223.5.5.5".into()),
        ]),
    );
    insert(&mut dns, "nameserver-policy", Value::Mapping(ns_policy));
    // 排除本地域名和 Windows 网络检测域名，使其不走 fake-ip
    insert(
        &mut dns,
        "fake-ip-filter",
        Value::Sequence(vec![
            Value::String("+.home".into()),
            Value::String("+.local".into()),
            Value::String("+.lan".into()),
            Value::String("+.internal".into()),
            Value::String("+.arpa".into()),
            Value::String("+.msftconnecttest.com".into()),
            Value::String("+.msftncsi.com".into()),
            Value::String("localhost.ptlogin2.qq.com".into()),
            Value::String("+.market.xiaomi.com".into()),
            Value::String("dns.msftncsi.com".into()),
            Value::String("www.msftncsi.com".into()),
            Value::String("www.msftconnecttest.com".into()),
        ]),
    );
    insert(&mut root, "dns", Value::Mapping(dns));
    if safe_search_enabled {
        insert(&mut root, "hosts", safe_search_hosts());
    } else {
        insert(&mut root, "hosts", Value::Mapping(Mapping::new()));
    }

    insert(&mut root, "proxies", Value::Sequence(proxies));
    let mut groups = imported_groups;
    let mut cleanweb_group = Mapping::new();
    insert(
        &mut cleanweb_group,
        "name",
        Value::String("CleanWeb".into()),
    );
    insert(
        &mut cleanweb_group,
        "type",
        Value::String("url-test".into()),
    );
    insert(
        &mut cleanweb_group,
        "url",
        Value::String("https://www.gstatic.com/generate_204".into()),
    );
    insert(&mut cleanweb_group, "interval", Value::Number(300.into()));
    insert(
        &mut cleanweb_group,
        "proxies",
        Value::Sequence(if proxy_names.is_empty() {
            vec![Value::String("DIRECT".into())]
        } else {
            proxy_names
        }),
    );
    groups.push(Value::Mapping(cleanweb_group));
    insert(&mut root, "proxy-groups", Value::Sequence(groups));

    let mut rules = load_filter_rules(&db)?;
    // 局域网/私有地址直连，确保内网设备（路由器等）可正常访问
    // 注意：不包含 198.18.0.0/16（fake-ip 范围），否则会拦截所有域名规则
    let lan_rules = [
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
        "IP-CIDR6,fd00::/8,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,home,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT",
    ];
    let mut all_rules: Vec<Value> = lan_rules
        .iter()
        .map(|r| Value::String((*r).into()))
        .collect();
    all_rules.append(&mut rules);
    all_rules.push(Value::String(format!(
        "MATCH,{}",
        if proxy_enabled { "CleanWeb" } else { "DIRECT" }
    )));
    insert(&mut root, "rules", Value::Sequence(all_rules));
    serde_yaml::to_string(&root).map_err(error)
}

fn load_filter_rules(db: &rusqlite::Connection) -> Result<Vec<Value>, String> {
    let enabled_categories = settings_map(db)?;
    let mut result = Vec::new();
    append_imported_rules(db, &enabled_categories, true, &mut result)?;
    let mut statement=db.prepare("SELECT kind,pattern,action FROM parent_rules WHERE enabled=1 ORDER BY CASE action WHEN 'block' THEN 0 ELSE 1 END,created_at").map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    for (kind, pattern, action) in rows {
        if let Some(rule) = mihomo_rule(
            &kind,
            &pattern,
            if action == "allow" {
                "DIRECT"
            } else {
                "REJECT"
            },
        ) {
            result.push(Value::String(rule));
        }
    }
    append_imported_rules(db, &enabled_categories, false, &mut result)?;
    Ok(result)
}

fn append_imported_rules(
    db: &rusqlite::Connection,
    settings: &std::collections::HashMap<String, String>,
    security_only: bool,
    result: &mut Vec<Value>,
) -> Result<(), String> {
    let comparator = if security_only {
        "IN ('fraud','phishing','malware')"
    } else {
        "NOT IN ('fraud','phishing','malware')"
    };
    let sql=format!("SELECT r.matcher_kind,r.pattern,r.action,r.category FROM imported_rules r JOIN subscriptions s ON s.id=r.subscription_id WHERE s.enabled=1 AND r.category {comparator} ORDER BY s.created_at,r.source_line");
    let mut statement = db.prepare(&sql).map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    for (kind, pattern, action, category) in rows {
        if settings
            .get(&format!("category.{category}"))
            .is_some_and(|value| value == "false")
        {
            continue;
        }
        if let Some(rule) = mihomo_rule(
            &kind,
            &pattern,
            if action == "Allow" {
                "DIRECT"
            } else {
                "REJECT"
            },
        ) {
            result.push(Value::String(rule));
        }
    }
    Ok(())
}

fn mihomo_rule(kind: &str, pattern: &str, target: &str) -> Option<String> {
    Some(match kind {
        "Exact" => format!("DOMAIN,{pattern},{target}"),
        "Suffix" => format!("DOMAIN-SUFFIX,{pattern},{target}"),
        "Contains" => format!("DOMAIN-KEYWORD,{pattern},{target}"),
        "Wildcard" => format!("DOMAIN-WILDCARD,{pattern},{target}"),
        "Regex" => format!("DOMAIN-REGEX,{pattern},{target}"),
        "Ip" | "Cidr" if pattern.contains(':') => format!("IP-CIDR6,{pattern},{target},no-resolve"),
        "Ip" | "Cidr" => format!("IP-CIDR,{pattern},{target},no-resolve"),
        _ => return None,
    })
}

fn safe_search_hosts() -> Value {
    let mut hosts = Mapping::new();
    for (domain, target) in [
        ("www.google.com", "forcesafesearch.google.com"),
        ("www.google.com.hk", "forcesafesearch.google.com"),
        ("www.bing.com", "strict.bing.com"),
        ("duckduckgo.com", "safe.duckduckgo.com"),
        ("www.youtube.com", "restrictmoderate.youtube.com"),
        ("m.youtube.com", "restrictmoderate.youtube.com"),
        ("youtubei.googleapis.com", "restrictmoderate.youtube.com"),
        ("youtube.googleapis.com", "restrictmoderate.youtube.com"),
    ] {
        hosts.insert(Value::String(domain.into()), Value::String(target.into()));
    }
    Value::Mapping(hosts)
}

/// 重新生成配置并通过 Mihomo API 热重载，无需重启进程。
pub fn reload_config(state: &AppState) -> Result<(), String> {
    let runtime = state.data_dir.join("mihomo");
    let secret = controller_secret(state)?;
    let config = build_config(state, &secret, true)?;
    let config_path = runtime.join("config.yaml");
    atomic_write(&config_path, config.as_bytes()).map_err(error)?;
    // 通过 Mihomo RESTful API 热重载配置
    let url = format!("http://{CONTROLLER}/configs?force=true");
    let body = serde_json::json!({
        "path": config_path.display().to_string()
    });
    let rt = tokio::runtime::Runtime::new().map_err(error)?;
    rt.block_on(async {
        reqwest::Client::new()
            .put(&url)
            .bearer_auth(&secret)
            .json(&body)
            .send()
            .await
            .map_err(error)?
            .error_for_status()
            .map_err(error)
    })?;
    Ok(())
}

/// 若保护正在运行则热重载配置，否则静默跳过。
pub fn try_reload_config(state: &AppState) {
    let running = match state.core_process.lock() {
        Ok(mut guard) => match guard.as_mut() {
            Some(child) => child.try_wait().ok().flatten().is_none(),
            None => false,
        },
        Err(_) => false,
    };
    if running {
        let _ = reload_config(state);
    }
}

pub(crate) fn controller_secret(state: &AppState) -> Result<String, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    if let Some(value) = db
        .query_row(
            "SELECT value FROM app_secrets WHERE key='controller_secret'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(error)?
    {
        return Ok(value);
    }
    let value = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO app_secrets(key,value) VALUES('controller_secret',?1)",
        params![value],
    )
    .map_err(error)?;
    Ok(value)
}

fn ensure_binary(app: &AppHandle, runtime: &Path) -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    if cfg!(target_arch = "aarch64") {
        return Err("Windows ARM64 is not supported".into());
    }
    let (asset, expected) = if cfg!(target_arch = "aarch64") {
        (ARM_GZ, ARM_SHA256)
    } else {
        (X64_GZ, X64_SHA256)
    };
    #[cfg(target_os = "windows")]
    let output = runtime.join("mihomo.exe");
    #[cfg(not(target_os = "windows"))]
    let output = runtime.join("mihomo");
    if output.is_file() {
        return Ok(output);
    }
    let resource = app
        .path()
        .resource_dir()
        .map_err(error)?
        .join("resources/mihomo")
        .join(asset);
    if !resource.is_file() {
        return Err(format!("缺少官方 Mihomo 内核资源：{}", resource.display()));
    }
    let bytes = fs::read(&resource).map_err(error)?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err("Mihomo 内核校验失败".into());
    }
    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut file = File::create(&output).map_err(error)?;
    io::copy(&mut decoder, &mut file).map_err(error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).map_err(error)?;
    }
    Ok(output)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = File::create(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temp, path)
}

fn deduplicate_named(values: &mut Vec<Value>) {
    let mut names = std::collections::HashSet::new();
    values.retain(|value| {
        value
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| names.insert(name.to_owned()))
    });
}
fn insert(map: &mut Mapping, key: &str, value: Value) {
    map.insert(Value::String(key.into()), value);
}
fn setting_bool(db: &rusqlite::Connection, key: &str) -> Result<bool, String> {
    Ok(db
        .query_row(
            "SELECT value FROM settings WHERE key=?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .map_err(error)?
        == "true")
}
fn settings_map(
    db: &rusqlite::Connection,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut statement = db
        .prepare("SELECT key,value FROM settings")
        .map_err(error)?;
    let values = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(error)?;
    Ok(values)
}
fn last_log_lines(path: &Path, count: usize) -> io::Result<String> {
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .rev()
        .take(count)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n"))
}
fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proxy_crypto::{encrypt_proxy_payload, test_key_env_lock},
        storage::AppState,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    #[test]
    fn generates_locked_fake_ip_config_and_filter_rules() {
        let _guard = test_key_env_lock();
        std::env::set_var("CLEANWEB_TEST_PROXY_KEY_B64", STANDARD.encode([4_u8; 32]));
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('r','rule','r','https://x',1)",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('r','1','Suffix','bad.example','Block','pornography',1)",[]).unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('p','proxy','p','https://x',1)",[]).unwrap();
            let payload=encrypt_proxy_payload("proxies:\n- name: node-a\n  type: ss\n  server: 127.0.0.1\n  port: 8388\n  cipher: aes-128-gcm\n  password: test\n").unwrap();
            db.execute(
                "INSERT INTO proxy_payloads(subscription_id,format,payload) VALUES('p','clash',?1)",
                params![payload],
            )
            .unwrap();
        }
        let config = build_config(&state, "secret", true).unwrap();
        assert!(config.contains("enhanced-mode: fake-ip"));
        assert!(config.contains("DOMAIN-SUFFIX,bad.example,REJECT"));
        assert!(config.contains("name: node-a"));
        assert!(!config.contains("controller_secret"));
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }
    #[test]
    fn network_conflict_shape_is_consistent() {
        let value = platform::detect_network_conflicts();
        assert_eq!(
            value.has_conflict,
            !value.interfaces.is_empty() || !value.vpn_services.is_empty()
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn official_arm_core_accepts_generated_config() {
        let asset = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/mihomo")
            .join(ARM_GZ);
        assert!(asset.is_file(), "official Mihomo ARM resource is missing");
        let bytes = fs::read(&asset).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), ARM_SHA256);
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("mihomo");
        let mut decoder = GzDecoder::new(bytes.as_slice());
        let mut file = File::create(&binary).unwrap();
        io::copy(&mut decoder, &mut file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _guard = test_key_env_lock();
        std::env::set_var("CLEANWEB_TEST_PROXY_KEY_B64", STANDARD.encode([5_u8; 32]));
        let state = AppState::open(directory.path().join("cleanweb.db")).unwrap();
        let config = build_config(&state, "test-secret", true).unwrap();
        let config_path = directory.path().join("config.yaml");
        fs::write(&config_path, config).unwrap();
        let output = Command::new(binary)
            .args(["-t", "-f"])
            .arg(&config_path)
            .arg("-d")
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }
}
