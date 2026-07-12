use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use std::process::Command;
#[cfg(not(target_os = "macos"))]
use std::{fs::OpenOptions, process::Stdio};

use flate2::read::GzDecoder;
use reqwest::Url;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize)]
struct SafeSearchManifest {
    version: u32,
    mappings: Vec<SafeSearchMapping>,
}

#[derive(Debug, Deserialize)]
struct SafeSearchMapping {
    domain: String,
    target: String,
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
            if platform::cleanweb_mihomo_running(saved) {
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
    let config_path = runtime.join("config.yaml");
    #[cfg(target_os = "macos")]
    let (pid, health_log) = platform::start_mihomo_privileged(&binary, &config_path)?;
    #[cfg(not(target_os = "macos"))]
    let (pid, health_log) = {
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
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|value| format!("无法启动 Mihomo：{value}"))?;
        let pid = child.id();
        *state.core_process.lock().map_err(|_| "内核状态不可用")? = Some(child);
        (pid, runtime.join("mihomo.log"))
    };
    fs::write(runtime.join("mihomo.pid"), pid.to_string()).map_err(error)?;
    let mut log = String::new();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        log = fs::read_to_string(&health_log).unwrap_or_default();
        if tun_startup_failed(&log) {
            platform::kill_process(pid);
            let _ = fs::remove_file(runtime.join("mihomo.pid"));
            return Err(
                last_log_lines(&health_log, 12).unwrap_or_else(|_| "Mihomo TUN 启动失败".into())
            );
        }
        if tun_startup_ready(&log) {
            break;
        }
        if !platform::pid_running(pid) {
            let _ = fs::remove_file(runtime.join("mihomo.pid"));
            return Err(
                last_log_lines(&health_log, 12).unwrap_or_else(|_| "Mihomo 启动后立即退出".into())
            );
        }
    }
    if !tun_startup_ready(&log) {
        platform::kill_process(pid);
        let _ = fs::remove_file(runtime.join("mihomo.pid"));
        return Err(
            last_log_lines(&health_log, 12).unwrap_or_else(|_| "等待 Mihomo TUN 就绪超时".into())
        );
    }
    core_status(state)
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
pub async fn reload_protection(
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    state.require_session(&session_token)?;
    let status = core_status(&state)?;
    if !status.running {
        return Ok(status);
    }
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(&app, &runtime)?;
    let secret = controller_secret(&state)?;
    let config_path = runtime.join("config.yaml");
    let config = build_config(&state, &secret, true)?;
    atomic_write(&config_path, config.as_bytes()).map_err(error)?;
    let validation = Command::new(binary)
        .args(["-t", "-f"])
        .arg(&config_path)
        .arg("-d")
        .arg(&runtime)
        .output()
        .map_err(|value| format!("无法校验 Mihomo 配置：{value}"))?;
    if !validation.status.success() {
        return Err(format!(
            "Mihomo 配置校验失败：{}",
            String::from_utf8_lossy(&validation.stderr).trim()
        ));
    }
    let mut url = Url::parse(&format!("http://{CONTROLLER}/configs")).map_err(error)?;
    url.query_pairs_mut().append_pair("force", "true");
    reqwest::Client::new()
        .put(url)
        .bearer_auth(secret)
        .json(&serde_json::json!({ "path": config_path }))
        .send()
        .await
        .map_err(error)?
        .error_for_status()
        .map_err(error)?;
    Ok(status)
}

#[tauri::command]
pub async fn test_proxy_group(
    group: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<DelayResult, String> {
    state.require_session(&session_token)?;
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/proxies")).map_err(error)?;
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
pub async fn get_proxies(session_token: String, state: State<'_, AppState>) -> Result<Vec<ProxyGroup>, String> {
    state.require_session(&session_token)?;
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
        let now = info
            .get("now")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
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
    session_token: String,
    state: State<'_, AppState>,
) -> Result<SubscriptionProxyInfo, String> {
    state.require_session(&session_token)?;
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
    session_token: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.require_session(&session_token)?;
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/proxies")).map_err(error)?;
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
    {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        db.execute(
            "INSERT INTO proxy_selections(group_name,proxy_name,updated_at) VALUES(?1,?2,CURRENT_TIMESTAMP) ON CONFLICT(group_name) DO UPDATE SET proxy_name=excluded.proxy_name,updated_at=CURRENT_TIMESTAMP",
            params![group, name],
        )
        .map_err(error)?;
        if group == "CleanWeb" {
            db.execute(
                "UPDATE settings SET value='false' WHERE key='automatic_node_selection'",
                [],
            )
            .map_err(error)?;
        }
    }
    Ok(())
}

/// 测试指定代理组中所有节点的延迟，返回每个节点的延迟值
#[tauri::command]
pub async fn test_all_proxy_delays(
    group: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<ProxyDelayResult, String> {
    state.require_session(&session_token)?;
    let secret = controller_secret(&state)?;
    let mut url = Url::parse(&format!("http://{CONTROLLER}/group")).map_err(error)?;
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
        if platform::cleanweb_mihomo_running(pid) {
            platform::terminate_process(pid);
            for _ in 0..20 {
                if !platform::cleanweb_mihomo_running(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if platform::cleanweb_mihomo_running(pid) {
                platform::kill_process(pid);
            }
        }
    }
    let _ = fs::remove_file(pid_path);
    Ok(())
}

fn core_status(state: &AppState) -> Result<CoreStatus, String> {
    let pid = read_pid(&state.data_dir.join("mihomo/mihomo.pid"))
        .filter(|pid| platform::cleanweb_mihomo_running(*pid));
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
    let safe_search_mappings = if safe_search_enabled {
        safe_search_mappings(&db)?
    } else {
        Vec::new()
    };
    let automatic_node_selection = setting_bool(&db, "automatic_node_selection")?;
    let selections: std::collections::HashMap<String, String> = {
        let mut statement = db
            .prepare("SELECT group_name,proxy_name FROM proxy_selections")
            .map_err(error)?;
        let values = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(error)?;
        values
    };
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
    let mut proxy_names: Vec<Value> = proxies
        .iter()
        .filter_map(|value| {
            value
                .get("name")
                .and_then(Value::as_str)
                .map(|name| Value::String(name.into()))
        })
        .collect();
    sanitize_proxy_groups(&mut imported_groups, &proxy_names);
    if let Some(selected) = selections.get("CleanWeb") {
        move_named_first(&mut proxy_names, selected);
    }
    if proxy_enabled && proxy_names.is_empty() {
        return Err(
            "已开启网络代理，但没有可用的代理节点；请先导入代理订阅，或关闭网络代理后再开启保护"
                .into(),
        );
    }

    let mut root = Mapping::new();
    insert(&mut root, "mixed-port", Value::Number(7890.into()));
    insert(&mut root, "allow-lan", Value::Bool(false));
    insert(&mut root, "mode", Value::String("rule".into()));
    insert(&mut root, "log-level", Value::String("info".into()));
    insert(&mut root, "ipv6", Value::Bool(true));
    insert(
        &mut root,
        "find-process-mode",
        Value::String("strict".into()),
    );
    insert(
        &mut root,
        "external-controller",
        Value::String(CONTROLLER.into()),
    );
    insert(&mut root, "secret", Value::String(secret.into()));

    let mut sniffer = Mapping::new();
    insert(&mut sniffer, "enable", Value::Bool(true));
    let mut sniff_protocols = Mapping::new();
    for (protocol, ports) in [
        ("HTTP", vec!["80", "8080-8880"]),
        ("TLS", vec!["443", "8443"]),
        ("QUIC", vec!["443", "8443"]),
    ] {
        let mut settings = Mapping::new();
        insert(
            &mut settings,
            "ports",
            Value::Sequence(ports.into_iter().map(|port| Value::String(port.into())).collect()),
        );
        insert(&mut settings, "override-destination", Value::Bool(true));
        sniff_protocols.insert(Value::String(protocol.into()), Value::Mapping(settings));
    }
    insert(&mut sniffer, "sniff", Value::Mapping(sniff_protocols));
    insert(&mut root, "sniffer", Value::Mapping(sniffer));

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
    insert(
        &mut dns,
        "proxy-server-nameserver",
        Value::Sequence(vec![
            Value::String("system://".into()),
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    insert(
        &mut dns,
        "direct-nameserver",
        Value::Sequence(vec![
            Value::String("system://".into()),
            Value::String("223.5.5.5".into()),
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
    // 排除本地域名、Windows 网络检测域名和搜索引擎域名，使其不走 fake-ip
    let mut fake_filter: Vec<String> = vec![
        "+.home",
        "+.local",
        "+.lan",
        "+.internal",
        "+.arpa",
        "+.msftconnecttest.com",
        "+.msftncsi.com",
        "localhost.ptlogin2.qq.com",
        "+.market.xiaomi.com",
        "dns.msftncsi.com",
        "www.msftncsi.com",
        "www.msftconnecttest.com",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    // 安全搜索需要真实 DNS 解析，将搜索引擎域名加入 fake-ip-filter
    if safe_search_enabled {
        for mapping in &safe_search_mappings {
            fake_filter.push(mapping.domain.clone());
        }
    }
    let fake_filter_values: Vec<Value> = fake_filter
        .iter()
        .map(|s| Value::String(s.clone()))
        .collect();
    insert(
        &mut dns,
        "fake-ip-filter",
        Value::Sequence(fake_filter_values),
    );
    insert(&mut root, "dns", Value::Mapping(dns));
    if safe_search_enabled {
        insert(&mut root, "hosts", safe_search_hosts(&safe_search_mappings));
    }

    insert(&mut root, "proxies", Value::Sequence(proxies));
    let mut groups = imported_groups;
    for group in &mut groups {
        let Some(mapping) = group.as_mapping_mut() else { continue };
        let Some(name) = mapping.get(Value::String("name".into())).and_then(Value::as_str) else { continue };
        let Some(selected) = selections.get(name) else { continue };
        if let Some(members) = mapping
            .get_mut(Value::String("proxies".into()))
            .and_then(Value::as_sequence_mut)
        {
            move_named_first(members, selected);
        }
    }
    let mut cleanweb_group = Mapping::new();
    insert(
        &mut cleanweb_group,
        "name",
        Value::String("CleanWeb".into()),
    );
    insert(
        &mut cleanweb_group,
        "type",
        Value::String(
            if automatic_node_selection {
                "url-test"
            } else {
                "select"
            }
            .into(),
        ),
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
    // 系统服务与国内直连域名，避免系统级与国内流量误走代理
    // 不依赖 GEOIP（需要 MMDB 文件），纯域名匹配确保国内常见服务直连
    let direct_rules = [
        // Apple 系统服务（推送通知、iCloud、App Store 等）
        "DOMAIN-SUFFIX,apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple.com.cn,DIRECT",
        "DOMAIN-SUFFIX,icloud.com,DIRECT",
        "DOMAIN-SUFFIX,icloud.com.cn,DIRECT",
        "DOMAIN-SUFFIX,mzstatic.com,DIRECT",
        "DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT",
        "DOMAIN-SUFFIX,cdn-apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple-mapkit.com,DIRECT",
        // Microsoft 系统服务（Windows 更新、推送等）
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",
        "DOMAIN-SUFFIX,windows.com,DIRECT",
        "DOMAIN-SUFFIX,msn.com,DIRECT",
        "DOMAIN-SUFFIX,live.com,DIRECT",
        "DOMAIN-SUFFIX,office.com,DIRECT",
        // 腾讯系（微信、QQ、腾讯云、腾讯文档 CDN 等）
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
        "DOMAIN-SUFFIX,tencent.com,DIRECT",
        "DOMAIN-SUFFIX,gtimg.com,DIRECT",
        "DOMAIN-SUFFIX,idqqimg.com,DIRECT",
        "DOMAIN-SUFFIX,qpic.cn,DIRECT",
        "DOMAIN-SUFFIX,myqcloud.com,DIRECT",
        "DOMAIN-SUFFIX,qcloud.com,DIRECT",
        "DOMAIN-SUFFIX,cdn.bcebos.com,DIRECT",
        // 阿里系（淘宝、天猫、支付宝、阿里云等）
        "DOMAIN-SUFFIX,alibaba.com,DIRECT",
        "DOMAIN-SUFFIX,alicdn.com,DIRECT",
        "DOMAIN-SUFFIX,aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,alipay.com,DIRECT",
        "DOMAIN-SUFFIX,alibabacloud.com,DIRECT",
        "DOMAIN-SUFFIX,mmstat.com,DIRECT",
        // 百度系
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,bdstatic.com,DIRECT",
        "DOMAIN-SUFFIX,bdimg.com,DIRECT",
        "DOMAIN-SUFFIX,bcebos.com,DIRECT",
        "DOMAIN-SUFFIX,bdydns.com,DIRECT",
        // 字节跳动系（抖音、飞书等）
        "DOMAIN-SUFFIX,bytedance.com,DIRECT",
        "DOMAIN-SUFFIX,byteimg.com,DIRECT",
        "DOMAIN-SUFFIX,douyin.com,DIRECT",
        "DOMAIN-SUFFIX,douyinpic.com,DIRECT",
        "DOMAIN-SUFFIX,feishu.cn,DIRECT",
        // 京东
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,360buy.com,DIRECT",
        "DOMAIN-SUFFIX,360buyimg.com,DIRECT",
        // 网易
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,netease.com,DIRECT",
        // 微博/新浪
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,sina.com.cn,DIRECT",
        "DOMAIN-SUFFIX,sinaimg.cn,DIRECT",
        "DOMAIN-SUFFIX,sinajs.com,DIRECT",
        // B站
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,bilivideo.com,DIRECT",
        "DOMAIN-SUFFIX,hdslb.com,DIRECT",
        "DOMAIN-SUFFIX,biliapi.net,DIRECT",
        // 美团/大众点评
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        // 拼多多
        "DOMAIN-SUFFIX,pinduoduo.com,DIRECT",
        "DOMAIN-SUFFIX,yangkeduo.com,DIRECT",
        // 小米
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
        "DOMAIN-SUFFIX,miui.com,DIRECT",
        // 华为
        "DOMAIN-SUFFIX,huawei.com,DIRECT",
        "DOMAIN-SUFFIX,dbankcdn.com,DIRECT",
        // 知乎/豆瓣/小红书
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,zhimg.com,DIRECT",
        "DOMAIN-SUFFIX,douban.com,DIRECT",
        "DOMAIN-SUFFIX,xiaohongshu.com,DIRECT",
        // 开发者/工具
        "DOMAIN-SUFFIX,csdn.net,DIRECT",
        "DOMAIN-SUFFIX,gitee.com,DIRECT",
        "DOMAIN-SUFFIX,oschina.net,DIRECT",
        // 政府/教育域名
        "DOMAIN-SUFFIX,gov.cn,DIRECT",
        "DOMAIN-SUFFIX,edu.cn,DIRECT",
        // 国内通用 CDN 与基础设施
        "DOMAIN-SUFFIX,cdn.bcebos.com,DIRECT",
        "DOMAIN-SUFFIX,qlogo.cn,DIRECT",
        "DOMAIN-SUFFIX,tencent-cloud.com,DIRECT",
    ];
    let mut all_rules: Vec<Value> = lan_rules
        .iter()
        .chain(direct_rules.iter())
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
    let mut statement=db.prepare("SELECT kind,pattern,action FROM parent_rules WHERE enabled=1 ORDER BY CASE action WHEN 'block' THEN 0 WHEN 'proxy' THEN 1 ELSE 2 END,created_at").map_err(error)?;
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
        let target = match action.as_str() {
            "allow" => "DIRECT",
            "proxy" => "CleanWeb",
            _ => "REJECT",
        };
        if let Some(rule) = mihomo_rule(&kind, &pattern, target) {
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

fn safe_search_manifest() -> Result<SafeSearchManifest, String> {
    let manifest: SafeSearchManifest = serde_yaml::from_str(include_str!(
        "../resources/safe-search/defaults.yaml"
    ))
    .map_err(|value| format!("内置安全搜索规则无效：{value}"))?;
    if manifest.version != 1 || manifest.mappings.is_empty() {
        return Err("内置安全搜索规则版本无效".into());
    }
    Ok(manifest)
}

fn safe_search_mappings(db: &rusqlite::Connection) -> Result<Vec<SafeSearchMapping>, String> {
    let mut mappings = safe_search_manifest()?.mappings;
    let mut statement = db.prepare("SELECT m.domain,m.target FROM safe_search_mappings m JOIN subscriptions s ON s.id=m.subscription_id WHERE s.enabled=1 AND s.kind='rule' ORDER BY s.created_at,m.source_line").map_err(error)?;
    let subscribed = statement
        .query_map([], |row| {
            Ok(SafeSearchMapping {
                domain: row.get(0)?,
                target: row.get(1)?,
            })
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    let mut indexes = std::collections::HashMap::new();
    for (index, mapping) in mappings.iter().enumerate() {
        indexes.insert(mapping.domain.clone(), index);
    }
    for mapping in subscribed {
        if let Some(index) = indexes.get(&mapping.domain).copied() {
            mappings[index] = mapping;
        } else {
            indexes.insert(mapping.domain.clone(), mappings.len());
            mappings.push(mapping);
        }
    }
    Ok(mappings)
}

fn safe_search_hosts(mappings: &[SafeSearchMapping]) -> Value {
    let mut hosts = Mapping::new();
    for mapping in mappings {
        hosts.insert(
            Value::String(mapping.domain.clone()),
            Value::String(mapping.target.clone()),
        );
    }
    Value::Mapping(hosts)
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
fn sanitize_proxy_groups(groups: &mut Vec<Value>, proxy_names: &[Value]) {
    let allowed_nodes: std::collections::HashSet<&str> =
        proxy_names.iter().filter_map(Value::as_str).collect();
    groups.retain_mut(|group| {
        let Some(source) = group.as_mapping() else {
            return false;
        };
        let Some(name) = source.get(Value::String("name".into())).and_then(Value::as_str) else {
            return false;
        };
        let group_type = source
            .get(Value::String("type".into()))
            .and_then(Value::as_str)
            .unwrap_or("select");
        if name.is_empty()
            || matches!(name, "CleanWeb" | "DIRECT" | "REJECT")
            || !matches!(group_type, "select" | "url-test" | "fallback" | "load-balance")
        {
            return false;
        }
        let members: Vec<Value> = source
            .get(Value::String("proxies".into()))
            .and_then(Value::as_sequence)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|member| allowed_nodes.contains(member))
            .map(|member| Value::String(member.into()))
            .collect();
        if members.is_empty() {
            return false;
        }
        let mut clean = Mapping::new();
        insert(&mut clean, "name", Value::String(name.into()));
        insert(&mut clean, "type", Value::String(group_type.into()));
        insert(&mut clean, "proxies", Value::Sequence(members));
        if group_type != "select" {
            insert(
                &mut clean,
                "url",
                Value::String("https://www.gstatic.com/generate_204".into()),
            );
            insert(&mut clean, "interval", Value::Number(300.into()));
        }
        *group = Value::Mapping(clean);
        true
    });
}
fn move_named_first(values: &mut Vec<Value>, selected: &str) {
    if let Some(index) = values.iter().position(|value| value.as_str() == Some(selected)) {
        let value = values.remove(index);
        values.insert(0, value);
    }
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

fn tun_startup_ready(log: &str) -> bool {
    let log = log.to_ascii_lowercase();
    // 旧版格式: "Tun[0] proxy listening at: utun5"
    // 新版格式: "[TUN] Tun adapter listening at: utun4(...)"
    (log.contains("tun[") && log.contains("proxy listening at:"))
        || log.contains("tun adapter listening at:")
}

fn tun_startup_failed(log: &str) -> bool {
    let log = log.to_ascii_lowercase();
    log.contains("start tun listening error")
        || log.contains("configure tun interface") && log.contains("operation not permitted")
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
        let yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert_eq!(
            yaml.get("hosts")
                .and_then(|hosts| hosts.get("www.google.com"))
                .and_then(Value::as_str),
            Some("forcesafesearch.google.com")
        );
        assert!(yaml.get("dns").and_then(|dns| dns.get("hosts")).is_none());
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }

    #[test]
    fn rejects_proxy_mode_without_any_usable_nodes() {
        let _guard = test_key_env_lock();
        std::env::set_var("CLEANWEB_TEST_PROXY_KEY_B64", STANDARD.encode([6_u8; 32]));
        let state = AppState::open(":memory:").unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE settings SET value='true' WHERE key='proxy_enabled'",
                [],
            )
            .unwrap();

        let error = build_config(&state, "secret", true).unwrap_err();

        assert!(error.contains("代理节点"), "{error}");
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

    #[test]
    fn rejects_a_live_core_when_tun_failed_to_start() {
        let log = r#"time=\"2026-07-11T15:23:32+08:00\" level=error msg=\"Start TUN listening error: configure tun interface: Connect: operation not permitted\""#;
        assert!(!tun_startup_ready(log));
        assert!(tun_startup_failed(log));
    }

    #[test]
    fn accepts_only_an_explicit_tun_ready_log() {
        // 旧版 mihomo 日志格式
        assert!(tun_startup_ready(
            "level=info msg=\"Tun[0] proxy listening at: utun5\""
        ));
        // 新版 mihomo 日志格式
        assert!(tun_startup_ready(
            "level=info msg=\"[TUN] Tun adapter listening at: utun4([198.18.0.1/30],[fdfe:dcba:9876::1/126]), mtu: 9000, auto route: true, auto redir: false, ip stack: Mixed\""
        ));
        assert!(!tun_startup_failed(
            "level=info msg=\"Tun[0] proxy listening at: utun5\""
        ));
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
