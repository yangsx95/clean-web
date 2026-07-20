use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
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

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxySelectionResult {
    pub requires_reload: bool,
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
    let status = core_status(&state)?;
    if status.running {
        return Ok(status);
    }
    start_inner(&app, &state)
}

fn start_inner(app: &AppHandle, state: &AppState) -> Result<CoreStatus, String> {
    stop_child(state)?;
    std::thread::sleep(Duration::from_millis(250));
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(app, &runtime)?;
    let secret = controller_secret(state)?;
    let config = build_config(state, &secret, true)?;
    let config_hash = config_hash(&config);
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
    atomic_write(
        &runtime.join("active-config"),
        format!("{pid}\n{config_hash}\n").as_bytes(),
    )
    .map_err(error)?;
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
    if state
        .reload_in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(status);
    }
    let result = reload_protection_inner(&app, &state, status).await;
    state.reload_in_progress.store(false, Ordering::Release);
    result
}

async fn reload_protection_inner(
    app: &AppHandle,
    state: &AppState,
    status: CoreStatus,
) -> Result<CoreStatus, String> {
    // 只能比较当前运行实例确认加载过的配置。用户目录中的 config.yaml 可能已经
    // 被新版本覆盖，而 root 内核仍运行旧配置；仅比较该文件会错误跳过安全搜索刷新。
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(app, &runtime)?;
    let secret = controller_secret(state)?;
    let new_config = build_config(state, &secret, true)?;
    if active_config_matches(&runtime.join("active-config"), status.pid, &new_config) {
        return Ok(status);
    }
    let config_path = runtime.join("config.yaml");
    atomic_write(&config_path, new_config.as_bytes()).map_err(error)?;
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
    let response = reqwest::Client::new()
        .put(url)
        .bearer_auth(&secret)
        .json(&serde_json::json!({ "path": config_path }))
        .send()
        .await
        .map_err(|value| format!("无法连接 Mihomo 热更新接口：{value}"))?;
    if !response.status().is_success() {
        let status_code = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!(
            "Mihomo 热更新失败（HTTP {status_code}）：{detail}。如果这是升级前启动的内核，请关闭保护后重新开启一次。"
        ));
    }
    if let Some(pid) = status.pid {
        atomic_write(
            &runtime.join("active-config"),
            format!("{pid}\n{}\n", config_hash(&new_config)).as_bytes(),
        )
        .map_err(error)?;
    }
    core_status(state)
}

fn config_hash(config: &str) -> String {
    format!("{:x}", Sha256::digest(config.as_bytes()))
}

fn active_config_matches(path: &Path, running_pid: Option<u32>, config: &str) -> bool {
    let Some(running_pid) = running_pid else {
        return false;
    };
    let Ok(marker) = fs::read_to_string(path) else {
        return false;
    };
    let mut lines = marker.lines();
    lines.next().and_then(|value| value.parse::<u32>().ok()) == Some(running_pid)
        && lines.next() == Some(config_hash(config).as_str())
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
pub async fn get_proxies(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<ProxyGroup>, String> {
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
) -> Result<ProxySelectionResult, String> {
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
    Ok(ProxySelectionResult {
        requires_reload: false,
    })
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
    platform::terminate_cleanweb_mihomo_processes();
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
            Value::Sequence(
                ports
                    .into_iter()
                    .map(|port| Value::String(port.into()))
                    .collect(),
            ),
        );
        insert(&mut settings, "override-destination", Value::Bool(true));
        sniff_protocols.insert(Value::String(protocol.into()), Value::Mapping(settings));
    }
    insert(&mut sniffer, "sniff", Value::Mapping(sniff_protocols));
    if safe_search_enabled {
        let mut skip_domains = Vec::new();
        for mapping in &safe_search_mappings {
            skip_domains.push(Value::String(mapping.domain.clone()));
            skip_domains.push(Value::String(mapping.target.clone()));
        }
        insert(&mut sniffer, "skip-domain", Value::Sequence(skip_domains));
    }
    insert(&mut root, "sniffer", Value::Mapping(sniffer));

    let mut tun = Mapping::new();
    insert(&mut tun, "enable", Value::Bool(tun_enabled));
    insert(&mut tun, "stack", Value::String("mixed".into()));
    insert(&mut tun, "device", Value::String("CleanWeb".into()));
    insert(&mut tun, "auto-route", Value::Bool(true));
    insert(&mut tun, "auto-detect-interface", Value::Bool(true));
    let dns_routes = dns_route_addresses(&platform::system_dns_servers());
    if !dns_routes.is_empty() {
        insert(
            &mut tun,
            "route-address",
            Value::Sequence(dns_routes.into_iter().map(Value::String).collect()),
        );
    }
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
    insert(
        &mut dns,
        "default-nameserver",
        Value::Sequence(vec![
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    insert(&mut dns, "respect-rules", Value::Bool(true));
    insert(&mut dns, "use-hosts", Value::Bool(true));
    insert(&mut dns, "use-system-hosts", Value::Bool(true));
    insert(
        &mut dns,
        "nameserver",
        Value::Sequence(vec![
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    insert(
        &mut dns,
        "proxy-server-nameserver",
        Value::Sequence(vec![
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    insert(
        &mut dns,
        "direct-nameserver",
        Value::Sequence(vec![
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    // 本地域名使用系统 DNS 解析，避免 fake-ip 导致无法访问路由器等内网设备
    let mut ns_policy = Mapping::new();
    insert(
        &mut ns_policy,
        "+.home,+.local,+.lan,+.internal,+.arpa",
        Value::Sequence(vec![
            Value::String("223.5.5.5".into()),
            Value::String("119.29.29.29".into()),
        ]),
    );
    insert(&mut dns, "nameserver-policy", Value::Mapping(ns_policy));
    // 排除本地域名和系统网络检测域名，使其不走 fake-ip。
    let fake_filter: Vec<String> = vec![
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
        let Some(mapping) = group.as_mapping_mut() else {
            continue;
        };
        let Some(name) = mapping
            .get(Value::String("name".into()))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(selected) = selections.get(name) else {
            continue;
        };
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
        "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve",
        "IP-CIDR,8.8.8.8/32,DIRECT,no-resolve",
        "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
        "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
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
        .map(|r| Value::String((*r).into()))
        .collect();
    all_rules.append(&mut rules);
    all_rules.extend(direct_rules.iter().map(|r| Value::String((*r).into())));
    all_rules.push(Value::String(format!(
        "MATCH,{}",
        if proxy_enabled { "CleanWeb" } else { "DIRECT" }
    )));
    insert(&mut root, "rules", Value::Sequence(all_rules));
    serde_yaml::to_string(&root).map_err(error)
}

fn dns_route_addresses(servers: &[String]) -> Vec<String> {
    std::iter::once("198.18.0.0/16".to_owned())
        .chain(servers.iter().filter_map(|server| {
            server
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|address| format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }))
        }))
        .collect()
}

fn load_filter_rules(db: &rusqlite::Connection) -> Result<Vec<Value>, String> {
    let enabled_categories = settings_map(db)?;
    let mut result = Vec::new();
    append_imported_rules(db, &enabled_categories, true, &mut result)?;
    if enabled_categories
        .get("strict_mode_enabled")
        .is_some_and(|value| value == "true")
    {
        append_strict_mode_rules(&mut result);
    }
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

fn append_strict_mode_rules(result: &mut Vec<Value>) {
    const STRICT_SUFFIXES: &[&str] = &[
        "yandex.com",
        "yandex.ru",
        "yandex.net",
        "yastatic.net",
        "yandexadexchange.net",
        "youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "googlevideo.com",
        "ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "telegram.org",
        "telegram.me",
        "t.me",
        "telegra.ph",
        "tdesktop.com",
        "instagram.com",
        "cdninstagram.com",
        "ig.me",
        "threads.net",
        "facebook.com",
        "fbcdn.net",
        "fb.com",
        "x.com",
        "twitter.com",
        "twimg.com",
        "t.co",
        "douyin.com",
        "tiktok.com",
        "tiktokv.com",
        "tiktokcdn.com",
        "muscdn.com",
        "byteoversea.com",
        "reddit.com",
        "redd.it",
        "redditmedia.com",
        "redditstatic.com",
        "tumblr.com",
        "tumblr.co",
        "tmblr.co",
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "snapchat.com",
        "pinterest.com",
        "pinimg.com",
        "cam",
        "sex",
        "sexy",
        "porn",
        "adult",
        "xxx",
        "xyz",
        "top",
        "click",
        "icu",
        "sbs",
        "cyou",
        "monster",
        "quest",
        "buzz",
        "fun",
        "lol",
        "rest",
        "cfd",
        "win",
        "men",
        "date",
        "party",
        "review",
        "trade",
        "download",
        "stream",
        "gdn",
        "zip",
        "mov",
        "tk",
        "ml",
        "ga",
        "gq",
        "cf",
        "bet",
        "casino",
        "poker",
        "bingo",
    ];
    const STRICT_KEYWORDS: &[&str] = &[
        "yandex",
        "youtube",
        "telegram",
        "instagram",
        "twitter",
        "tiktok",
        "porn",
        "porno",
        "sex",
        "sexy",
        "xxx",
        "adult",
        "nude",
        "naked",
        "onlyfans",
        "camgirl",
        "livecam",
        "jav",
        "hentai",
        "rule34",
        "91",
    ];
    const STRICT_CIDRS: &[&str] = &[
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.12.0/22",
        "91.108.16.0/22",
        "91.108.20.0/22",
        "91.108.56.0/22",
        "149.154.160.0/20",
    ];
    for suffix in STRICT_SUFFIXES {
        result.push(Value::String(format!("DOMAIN-SUFFIX,{suffix},REJECT")));
    }
    for keyword in STRICT_KEYWORDS {
        result.push(Value::String(format!("DOMAIN-KEYWORD,{keyword},REJECT")));
    }
    for cidr in STRICT_CIDRS {
        result.push(Value::String(format!("IP-CIDR,{cidr},REJECT,no-resolve")));
    }
    result.push(Value::String(
        "DOMAIN-REGEX,(^|[.])[a-z0-9-]*[0-9]{5}[0-9]*[a-z0-9-]*([.]|$),REJECT".into(),
    ));
    result.push(Value::String(
        "DOMAIN-REGEX,(^|[.])[0-9a-f]{8}[0-9a-f]*([.]|$),REJECT".into(),
    ));
    result.push(Value::String(
        "DOMAIN-REGEX,(^|[.])[bcdfghjklmnpqrstvwxyz0-9]{7}[bcdfghjklmnpqrstvwxyz0-9]*([.]|$),REJECT".into(),
    ));
    result.push(Value::String(
        "DOMAIN-REGEX,(^|[.])[a-z][a-z]*[0-9]{4}[0-9]*[a-z][a-z]*([.]|$),REJECT".into(),
    ));
    result.push(Value::String(
        "DOMAIN-REGEX,(^|[.])[a-z0-9-]{20}[a-z0-9-]*([.]|$),REJECT".into(),
    ));
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
    let manifest: SafeSearchManifest =
        serde_yaml::from_str(include_str!("../resources/safe-search/defaults.yaml"))
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
    // 阻断常见 DoH 服务器，强制浏览器回退到普通 DNS，
    // 否则加密的 DNS 查询会绕过 hosts 重定向，安全搜索失效
    let doh_servers = [
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "dns.microsoft",
        "doh.opendns.com",
        "dns.quad9.net",
        "dns.adguard.com",
        "dns-family.adguard.com",
        "security.cloudflare-dns.com",
    ];
    for server in doh_servers {
        hosts.insert(
            Value::String(server.to_string()),
            Value::String("127.0.0.1".to_string()),
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
        let Some(name) = source
            .get(Value::String("name".into()))
            .and_then(Value::as_str)
        else {
            return false;
        };
        let group_type = source
            .get(Value::String("type".into()))
            .and_then(Value::as_str)
            .unwrap_or("select");
        if name.is_empty()
            || matches!(name, "CleanWeb" | "DIRECT" | "REJECT")
            || !matches!(
                group_type,
                "select" | "url-test" | "fallback" | "load-balance"
            )
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
    if let Some(index) = values
        .iter()
        .position(|value| value.as_str() == Some(selected))
    {
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
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('parent-block','block','Suffix','baidu.com','custom')",
                [],
            )
            .unwrap();
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
        let parent_block = config.find("DOMAIN-SUFFIX,baidu.com,REJECT").unwrap();
        let built_in_direct = config.find("DOMAIN-SUFFIX,baidu.com,DIRECT").unwrap();
        assert!(
            parent_block < built_in_direct,
            "家长拦截规则必须先于内置的代理路由规则"
        );
        assert!(config.contains("name: node-a"));
        assert!(!config.contains("controller_secret"));
        let yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert!(
            yaml.get("mixed-port").is_none(),
            "TUN 模式不得向其他应用暴露本地代理端口"
        );
        assert_eq!(
            yaml.get("dns")
                .and_then(|dns| dns.get("respect-rules"))
                .and_then(Value::as_bool),
            Some(true),
            "DNS 上游请求必须遵循代理规则，否则 Google 安全搜索目标可能无法解析"
        );
        assert_eq!(
            yaml.get("dns")
                .and_then(|dns| dns.get("default-nameserver"))
                .and_then(Value::as_sequence)
                .map(|values| values.contains(&Value::String("223.5.5.5".into()))),
            Some(true),
            "代理节点域名和 DNS 上游需要直连 bootstrap DNS，避免启动时解析自举死锁"
        );
        let config_rules = yaml
            .get("rules")
            .and_then(Value::as_sequence)
            .expect("generated rules");
        assert!(config_rules.contains(&Value::String(
            "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve".into()
        )));
        assert!(config_rules.contains(&Value::String(
            "IP-CIDR,8.8.8.8/32,DIRECT,no-resolve".into()
        )));
        assert_eq!(
            yaml.get("hosts")
                .and_then(|hosts| hosts.get("www.google.com"))
                .and_then(Value::as_str),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            yaml.get("hosts")
                .and_then(|hosts| hosts.get("www.google.*"))
                .and_then(Value::as_str),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            yaml.get("hosts")
                .and_then(|hosts| hosts.get("www.youtube-nocookie.com"))
                .and_then(Value::as_str),
            Some("restrictmoderate.youtube.com")
        );
        let fake_ip_filter = yaml
            .get("dns")
            .and_then(|dns| dns.get("fake-ip-filter"))
            .and_then(Value::as_sequence)
            .unwrap();
        assert!(!fake_ip_filter.contains(&Value::String("www.google.*".into())));
        assert!(!fake_ip_filter.contains(&Value::String("www.youtube-nocookie.com".into())));
        assert!(yaml.get("dns").and_then(|dns| dns.get("hosts")).is_none());
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }

    #[test]
    fn strict_mode_adds_heuristic_reject_rules_only_when_enabled() {
        let state = AppState::open(":memory:").unwrap();
        let default_config = build_config(&state, "secret", true).unwrap();
        assert!(!default_config.contains("DOMAIN-KEYWORD,porn,REJECT"));
        assert!(!default_config.contains("DOMAIN-SUFFIX,youtube.com,REJECT"));
        assert!(!default_config.contains("IP-CIDR,91.108.4.0/22,REJECT,no-resolve"));
        assert!(
            !default_config.contains("DOMAIN-REGEX,(^|[.])[a-z0-9-]{20}[a-z0-9-]*([.]|$),REJECT")
        );

        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE settings SET value='true' WHERE key='strict_mode_enabled'",
                [],
            )
            .unwrap();
        }
        let strict_config = build_config(&state, "secret", true).unwrap();
        assert!(strict_config.contains("DOMAIN-SUFFIX,youtube.com,REJECT"));
        assert!(strict_config.contains("DOMAIN-KEYWORD,porn,REJECT"));
        assert!(strict_config.contains("DOMAIN-KEYWORD,91,REJECT"));
        assert!(strict_config.contains("IP-CIDR,91.108.4.0/22,REJECT,no-resolve"));
        assert!(strict_config.contains("DOMAIN-REGEX,(^|[.])[a-z0-9-]{20}[a-z0-9-]*([.]|$),REJECT"));
    }

    #[test]
    fn does_not_treat_a_stale_disk_config_as_the_active_safe_search_config() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("active-config");
        let config = "hosts:\n  www.google.com: forcesafesearch.google.com\n";

        // 回归场景：config.yaml 已被新版本写入，但正在运行的 root 内核没有加载它。
        assert!(!active_config_matches(&marker, Some(42), config));
        fs::write(&marker, format!("41\n{}\n", config_hash(config))).unwrap();
        assert!(!active_config_matches(&marker, Some(42), config));

        fs::write(&marker, format!("42\n{}\n", config_hash(config))).unwrap();
        assert!(active_config_matches(&marker, Some(42), config));
    }

    #[test]
    fn adds_exact_tun_routes_for_lan_dns_servers() {
        let routes =
            dns_route_addresses(&["10.195.85.120".into(), "240e:479:4e90:3e59::19".into()]);

        assert!(!routes.contains(&"0.0.0.0/1".into()));
        assert!(!routes.contains(&"128.0.0.0/1".into()));
        assert!(routes.contains(&"198.18.0.0/16".into()));
        assert!(routes.contains(&"10.195.85.120/32".into()));
        assert!(routes.contains(&"240e:479:4e90:3e59::19/128".into()));
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
