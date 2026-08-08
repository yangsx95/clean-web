use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use std::process::Command;
#[cfg(not(target_os = "macos"))]
use std::process::Stdio;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use flate2::read::GzDecoder;
use reqwest::Url;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

use crate::{
    dns_filter,
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
#[cfg(target_os = "macos")]
const ARM_BINARY_SHA256: &str = "55b7286331cb30a54b2564013b02b84a0c280e8b690bd1e5da4b9d4f4ca007ac";
#[cfg(target_os = "macos")]
const X64_BINARY_SHA256: &str = "35db993895dc2dc7f039cc8e6367c2ef6078d8bc887da2cff12e8cec5307e9d3";

#[cfg(target_os = "windows")]
const ARM_GZ: &str = "mihomo-windows-arm64-v1.19.28.gz";
#[cfg(target_os = "windows")]
const X64_GZ: &str = "mihomo-windows-amd64-v1.19.28.gz";
#[cfg(target_os = "windows")]
const ARM_SHA256: &str = "be4669b85eaae8c9620123001e1b10c5ef0253ffcc2042c873f97cf77b9fc0a1";
#[cfg(target_os = "windows")]
const X64_SHA256: &str = "16c476b5b80f3b6b120d2bb49f8b79626a5ad7f79c2898dac848f2730bc24944";
#[cfg(target_os = "windows")]
const ARM_BINARY_SHA256: &str = "8e77504f9eabb64b03852e056eef69c4a6928f9178d485ad61c14d2b0b8b98b9";
#[cfg(target_os = "windows")]
const X64_BINARY_SHA256: &str = "84f8bcd390ee146cba87746fe5447eb1bfa534c8f03c52dd965ef207ae4f0eeb";
const CONTROLLER: &str = "127.0.0.1:19090";
const SYSTEM_DNS_CACHE_FILE: &str = "mihomo/system-dns-servers.json";
const PROTECTION_HEALTH_FAILURE_LIMIT: u32 = 3;
const PROTECTION_START_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const RUNTIME_PROGRESS_EVENT: &str = "runtime-progress";

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct MihomoAsset {
    archive: &'static str,
    archive_sha256: &'static str,
    binary_sha256: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub controller: String,
    pub config_path: String,
    pub components: Vec<CoreComponentStatus>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreComponentStatus {
    pub id: String,
    pub label: String,
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProgress {
    pub operation: String,
    pub phase: String,
    pub percent: u8,
    pub message: String,
    pub components: Vec<CoreComponentStatus>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelayResult {
    pub delay: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConnectivityResult {
    pub url: String,
    pub group: String,
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

#[tauri::command]
pub fn get_network_conflicts() -> NetworkConflicts {
    platform::detect_network_conflicts()
}

#[tauri::command]
pub fn get_core_status(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    core_status(&state)
}

#[tauri::command]
pub async fn start_protection(session_token: String, app: AppHandle) -> Result<CoreStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        state.require_session(&session_token)?;
        start_protection_exclusive(&app, &state)
    })
    .await
    .map_err(error)?
}

#[tauri::command]
pub async fn auto_start_protection(app: AppHandle) -> Result<CoreStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        auto_start_protection_inner(&app, &state)
    })
    .await
    .map_err(error)?
}

pub(crate) fn auto_start_protection_inner(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreStatus, String> {
    append_runtime_startup_log(state, "auto start: checking persisted setting");
    let protection_enabled = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        setting_bool(&db, "protection_enabled")?
    };
    if !protection_enabled {
        append_runtime_startup_log(state, "auto start: skipped because protection is disabled");
        return core_status(state);
    }
    append_runtime_startup_log(state, "auto start: checking current runtime status");
    let status = core_status(state)?;
    if status.running {
        append_runtime_startup_log(state, "auto start: existing runtime is healthy");
        return Ok(status);
    }
    append_runtime_startup_log(state, "auto start: starting runtime");
    start_protection_exclusive(app, state)
}

fn start_protection_exclusive(app: &AppHandle, state: &AppState) -> Result<CoreStatus, String> {
    if state
        .protection_start_in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return wait_for_protection_start(state);
    }
    let result = start_inner(app, state);
    state
        .protection_start_in_progress
        .store(false, Ordering::Release);
    result
}

fn wait_for_protection_start(state: &AppState) -> Result<CoreStatus, String> {
    let deadline = Instant::now() + PROTECTION_START_WAIT_TIMEOUT;
    while state.protection_start_in_progress.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    core_status(state)
}

fn append_runtime_startup_log(state: &AppState, message: impl AsRef<str>) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.data_dir.join("startup.log"))
    {
        let _ = writeln!(file, "{}", message.as_ref());
    }
}

fn start_inner(app: &AppHandle, state: &AppState) -> Result<CoreStatus, String> {
    let startup_started = Instant::now();
    emit_runtime_progress(
        app,
        "start",
        "preparing",
        4,
        "准备启动保护",
        core_components(false, false, false, false),
    );
    refresh_system_dns_servers(state)?;
    log_startup_phase(app, "start", "refresh initial DNS", 10, startup_started);
    stop_child(state)?;
    log_startup_phase(app, "start", "stop previous runtime", 18, startup_started);
    std::thread::sleep(Duration::from_millis(250));
    refresh_system_dns_servers(state)?;
    log_startup_phase(app, "start", "refresh DNS after stop", 24, startup_started);
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(app, &runtime)?;
    log_startup_phase(app, "start", "ensure mihomo binary", 32, startup_started);
    let secret = controller_secret(state)?;
    let config = build_config(state, &secret, true)?;
    log_startup_phase(app, "start", "build mihomo config", 42, startup_started);
    let config_hash = config_hash(&config);
    atomic_write(&runtime.join("config.yaml"), config.as_bytes()).map_err(error)?;
    log_startup_phase(app, "start", "write mihomo config", 48, startup_started);
    let config_path = runtime.join("config.yaml");
    #[cfg(target_os = "macos")]
    let (pid, health_log, health_log_offset) = {
        let (pid, health_log) = platform::start_mihomo_privileged(&binary, &config_path)?;
        (pid, health_log, 0)
    };
    #[cfg(not(target_os = "macos"))]
    let (pid, health_log, health_log_offset) = {
        let health_log = runtime.join("mihomo.log");
        let health_log_offset = fs::metadata(&health_log)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&health_log)
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
        (pid, health_log, health_log_offset)
    };
    emit_runtime_progress(
        app,
        "start",
        "start mihomo process",
        58,
        "保护内核已启动，等待网络接管",
        core_components(true, false, false, false),
    );
    log_startup_phase(app, "start", "start mihomo process", 58, startup_started);
    if let Err(reason) = dns_filter::start_dns_filter(state) {
        platform::kill_process(pid);
        emit_runtime_failure(app, "start", "start DNS filter", &reason);
        return Err(reason);
    }
    emit_runtime_progress(
        app,
        "start",
        "start DNS filter",
        68,
        "CleanWeb DNS 过滤器已启动",
        core_components(true, false, true, false),
    );
    log_startup_phase(app, "start", "start DNS filter", 68, startup_started);
    if let Err(reason) = fs::write(runtime.join("mihomo.pid"), pid.to_string()).map_err(error) {
        platform::kill_process(pid);
        let _ = dns_filter::stop_dns_filter(state);
        emit_runtime_failure(app, "start", "write mihomo pid", &reason);
        return Err(reason);
    }
    log_startup_phase(app, "start", "write mihomo pid", 72, startup_started);
    let mut log = String::new();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        log = read_log_since(&health_log, health_log_offset).unwrap_or_default();
        if tun_startup_failed(&log) {
            platform::kill_process(pid);
            let _ = dns_filter::stop_dns_filter(state);
            let _ = fs::remove_file(runtime.join("mihomo.pid"));
            let reason =
                last_log_lines(&health_log, 12).unwrap_or_else(|_| "Mihomo TUN 启动失败".into());
            emit_runtime_failure(app, "start", "wait mihomo TUN ready", &reason);
            return Err(reason);
        }
        if !platform::pid_running(pid) {
            let _ = dns_filter::stop_dns_filter(state);
            let _ = fs::remove_file(runtime.join("mihomo.pid"));
            let reason =
                last_log_lines(&health_log, 12).unwrap_or_else(|_| "Mihomo 启动后立即退出".into());
            emit_runtime_failure(app, "start", "start mihomo process", &reason);
            return Err(reason);
        }
        if tun_startup_ready(&log) {
            break;
        }
    }
    log_startup_phase(app, "start", "wait mihomo TUN ready", 82, startup_started);
    if !tun_startup_ready(&log) {
        platform::kill_process(pid);
        let _ = dns_filter::stop_dns_filter(state);
        let _ = fs::remove_file(runtime.join("mihomo.pid"));
        let reason =
            last_log_lines(&health_log, 12).unwrap_or_else(|_| "等待 Mihomo TUN 就绪超时".into());
        emit_runtime_failure(app, "start", "wait mihomo TUN ready", &reason);
        return Err(reason);
    }
    if let Err(reason) = atomic_write(
        &runtime.join("active-config"),
        format!("{pid}\n{config_hash}\n").as_bytes(),
    )
    .map_err(error)
    {
        platform::kill_process(pid);
        let _ = dns_filter::stop_dns_filter(state);
        let _ = fs::remove_file(runtime.join("mihomo.pid"));
        emit_runtime_failure(app, "start", "write active config", &reason);
        return Err(reason);
    }
    emit_runtime_progress(
        app,
        "start",
        "write active config",
        90,
        "运行配置已记录",
        core_components(true, true, true, false),
    );
    log_startup_phase(app, "start", "write active config", 90, startup_started);
    let status = core_status(state);
    if let Ok(status) = &status {
        emit_runtime_progress(
            app,
            "start",
            "verify protection health",
            if status.running { 100 } else { 96 },
            if status.running {
                "保护组件已全部就绪"
            } else {
                "保护组件仍在检测中"
            },
            status.components.clone(),
        );
    }
    log_startup_phase(
        app,
        "start",
        "verify protection health",
        100,
        startup_started,
    );
    status
}

fn refresh_system_dns_servers(state: &AppState) -> Result<(), String> {
    let discovered_dns_servers = platform::system_dns_servers();
    let cached_dns_servers = if discovered_dns_servers.is_empty() {
        read_cached_system_dns_servers(state)
    } else {
        Vec::new()
    };
    let mut guard = state
        .system_dns_servers
        .lock()
        .map_err(|_| "系统 DNS 状态不可用")?;
    let selected = select_system_dns_servers(&discovered_dns_servers, &guard, &cached_dns_servers);
    if selected != *guard {
        *guard = selected.clone();
    }
    drop(guard);
    if !discovered_dns_servers.is_empty() {
        write_cached_system_dns_servers(state, &discovered_dns_servers)?;
    }
    Ok(())
}

fn select_system_dns_servers(
    discovered_dns_servers: &[String],
    current_dns_servers: &[String],
    cached_dns_servers: &[String],
) -> Vec<String> {
    if !discovered_dns_servers.is_empty() {
        return discovered_dns_servers.to_vec();
    }
    if !current_dns_servers.is_empty() {
        return current_dns_servers.to_vec();
    }
    cached_dns_servers.to_vec()
}

fn read_cached_system_dns_servers(state: &AppState) -> Vec<String> {
    let path = state.data_dir.join(SYSTEM_DNS_CACHE_FILE);
    fs::read_to_string(path)
        .ok()
        .and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .map(|values| {
            values
                .into_iter()
                .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
                .collect()
        })
        .unwrap_or_default()
}

fn write_cached_system_dns_servers(state: &AppState, dns_servers: &[String]) -> Result<(), String> {
    let path = state.data_dir.join(SYSTEM_DNS_CACHE_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(error)?;
    }
    let body = serde_json::to_vec(dns_servers).map_err(error)?;
    atomic_write(&path, &body).map_err(error)
}

#[tauri::command]
pub async fn stop_protection(session_token: String, app: AppHandle) -> Result<CoreStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        state.require_session(&session_token)?;
        stop_child(&state)?;
        core_status(&state)
    })
    .await
    .map_err(error)?
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
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        reload_protection_inner(&app, &state, status)
    })
    .await
    .map_err(error)
    .and_then(|value| value);
    state.reload_in_progress.store(false, Ordering::Release);
    result
}

fn reload_protection_inner(
    app: &AppHandle,
    state: &AppState,
    _status: CoreStatus,
) -> Result<CoreStatus, String> {
    // Mihomo 控制器可用不代表系统 TUN fd 仍然健康。热更新后曾出现
    // "batch read packet: bad file descriptor"：代理测速和控制 API 正常，
    // 但浏览器 TUN 流量全部失败。重载运行配置时保守重启内核，
    // 重新创建 TUN 设备和路由，避免把坏数据面误判为正常。
    let runtime = state.data_dir.join("mihomo");
    fs::create_dir_all(&runtime).map_err(error)?;
    let binary = ensure_binary(app, &runtime)?;
    let secret = controller_secret(state)?;
    let new_config = build_config(state, &secret, true)?;
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
    start_inner(app, state)
}

fn config_hash(config: &str) -> String {
    format!("{:x}", Sha256::digest(config.as_bytes()))
}

#[cfg(test)]
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
    let delay = proxy_group_delay(&secret, &group, "https://www.gstatic.com/generate_204").await?;
    Ok(DelayResult { delay })
}

#[tauri::command]
pub async fn test_proxy_connectivity(
    target: String,
    group: String,
    session_token: String,
    state: State<'_, AppState>,
) -> Result<ProxyConnectivityResult, String> {
    state.require_session(&session_token)?;
    let target = normalize_connectivity_target(&target)?;
    let secret = controller_secret(&state)?;
    let delay = proxy_group_delay(&secret, &group, &target).await?;
    Ok(ProxyConnectivityResult {
        url: target,
        group,
        delay,
    })
}

async fn proxy_group_delay(secret: &str, group: &str, target: &str) -> Result<u64, String> {
    let mut url = Url::parse(&format!("http://{CONTROLLER}/proxies")).map_err(error)?;
    url.path_segments_mut()
        .map_err(|_| "控制器地址无效")?
        .push(group)
        .push("delay");
    url.query_pairs_mut()
        .append_pair("url", target)
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
    Ok(delay)
}

fn normalize_connectivity_target(target: &str) -> Result<String, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("请输入要检测的网址或域名".into());
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&candidate).map_err(|_| "请输入有效的网址或域名")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("仅支持 HTTP/HTTPS 连通性检测".into());
    }
    if parsed.host_str().is_none() {
        return Err("请输入包含域名或 IP 的地址".into());
    }
    Ok(parsed.to_string())
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

pub(crate) fn stop_child(state: &AppState) -> Result<(), String> {
    reset_protection_health_failures(state);
    dns_filter::stop_dns_filter(state)?;
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
    #[cfg(target_os = "macos")]
    {
        platform::stop_mihomo_privileged()?;
        let _ = fs::remove_file(pid_path);
        let _ = fs::remove_file(state.data_dir.join("mihomo/active-config"));
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
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
}

fn core_status(state: &AppState) -> Result<CoreStatus, String> {
    let pid_path = state.data_dir.join("mihomo/mihomo.pid");
    let active_config_path = state.data_dir.join("mihomo/active-config");
    let pid = current_core_pid(state, &pid_path)?;
    let active_config_present = active_config_path.exists();
    let cleanweb_dns_ready =
        pid.is_some() && active_config_present && dns_filter::dns_filter_running(state);
    let mihomo_dns_ready = cleanweb_dns_ready;
    let running = protection_resources_healthy(
        pid.is_some(),
        active_config_present,
        cleanweb_dns_ready,
        mihomo_dns_ready,
    );
    if running {
        reset_protection_health_failures(state);
    } else if should_recover_incomplete_protection_state(
        state,
        pid.is_some(),
        active_config_present,
    ) {
        recover_incomplete_protection_state(state, &pid_path);
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
        components: core_components(
            pid.is_some(),
            active_config_present,
            cleanweb_dns_ready,
            mihomo_dns_ready,
        ),
    })
}

fn core_components(
    mihomo_running: bool,
    active_config_present: bool,
    cleanweb_dns_ready: bool,
    mihomo_dns_ready: bool,
) -> Vec<CoreComponentStatus> {
    vec![
        component_status(
            "mihomo",
            "Mihomo 内核",
            mihomo_running,
            "进程运行中",
            "未检测到运行进程",
        ),
        component_status(
            "active-config",
            "运行配置",
            active_config_present,
            "已记录当前配置",
            "缺少 active-config",
        ),
        component_status(
            "cleanweb-dns",
            "CleanWeb DNS",
            cleanweb_dns_ready,
            "DNS 过滤线程已启动",
            "DNS 过滤未启动",
        ),
        component_status(
            "mihomo-dns",
            "本机 DNS 接管",
            mihomo_dns_ready,
            "DNS 接管已随内核运行",
            "系统 DNS 未接管",
        ),
    ]
}

fn component_status(
    id: &str,
    label: &str,
    healthy: bool,
    ready_detail: &str,
    failed_detail: &str,
) -> CoreComponentStatus {
    CoreComponentStatus {
        id: id.into(),
        label: label.into(),
        status: if healthy { "ready" } else { "stopped" }.into(),
        detail: if healthy { ready_detail } else { failed_detail }.into(),
    }
}

fn should_recover_incomplete_protection_state(
    state: &AppState,
    mihomo_running: bool,
    active_config_present: bool,
) -> bool {
    if !mihomo_running {
        return true;
    }
    if !active_config_present {
        return record_protection_health_failure(state) >= PROTECTION_HEALTH_FAILURE_LIMIT;
    }
    false
}

fn record_protection_health_failure(state: &AppState) -> u32 {
    let Ok(mut failures) = state.protection_health_failures.lock() else {
        return PROTECTION_HEALTH_FAILURE_LIMIT;
    };
    *failures = failures.saturating_add(1);
    *failures
}

fn reset_protection_health_failures(state: &AppState) {
    if let Ok(mut failures) = state.protection_health_failures.lock() {
        *failures = 0;
    }
}

fn current_core_pid(state: &AppState, pid_path: &Path) -> Result<Option<u32>, String> {
    let mut process = state.core_process.lock().map_err(|_| "内核状态不可用")?;
    if let Some(child) = process.as_mut() {
        match child.try_wait().map_err(error)? {
            None => return Ok(Some(child.id())),
            Some(_) => *process = None,
        }
    }
    Ok(read_pid(pid_path).filter(|pid| platform::cleanweb_mihomo_running(*pid)))
}

fn protection_resources_healthy(
    mihomo_running: bool,
    active_config_present: bool,
    cleanweb_dns_ready: bool,
    mihomo_dns_ready: bool,
) -> bool {
    mihomo_running && active_config_present && cleanweb_dns_ready && mihomo_dns_ready
}

fn dns_upstream_route_excludes(upstreams: &[String]) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    upstreams
        .iter()
        .filter_map(|value| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .filter(|address| seen.insert(*address))
        .map(|address| {
            Value::String(match address {
                std::net::IpAddr::V4(address) => format!("{address}/32"),
                std::net::IpAddr::V6(address) => format!("{address}/128"),
            })
        })
        .collect()
}

fn recover_incomplete_protection_state(_state: &AppState, _pid_path: &Path) {
    let _ = dns_filter::stop_dns_filter(_state);
    #[cfg(target_os = "macos")]
    if _state.data_dir.join("mihomo/active-config").exists() {
        let _ = platform::stop_mihomo_privileged();
    }
    let _ = fs::remove_file(_pid_path);
    let _ = fs::remove_file(_state.data_dir.join("mihomo/active-config"));
}
fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn build_config(state: &AppState, secret: &str, tun_enabled: bool) -> Result<String, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    let proxy_enabled = setting_bool(&db, "proxy_enabled")?;
    let access_logging_enabled = setting_bool(&db, "access_logging_enabled")?;
    let automatic_node_selection = setting_bool(&db, "automatic_node_selection")?;
    let system_dns_servers = state
        .system_dns_servers
        .lock()
        .map_err(|_| "系统 DNS 状态不可用")?
        .clone();
    let dns_upstreams =
        dns_filter::effective_dns_upstreams(&system_dns_servers, configured_dns_upstreams(&db)?);
    let dns_upstream_values: Vec<Value> = dns_upstreams
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect();
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
    insert(&mut root, "unified-delay", Value::Bool(true));
    insert(&mut root, "tcp-concurrent", Value::Bool(true));
    insert(
        &mut root,
        "log-level",
        Value::String(
            if access_logging_enabled {
                "info"
            } else {
                "warning"
            }
            .into(),
        ),
    );
    insert(&mut root, "ipv6", Value::Bool(true));
    insert(
        &mut root,
        "find-process-mode",
        Value::String(
            if access_logging_enabled {
                "strict"
            } else {
                "off"
            }
            .into(),
        ),
    );
    insert(
        &mut root,
        "external-controller",
        Value::String(CONTROLLER.into()),
    );
    insert(&mut root, "secret", Value::String(secret.into()));
    let mut profile = Mapping::new();
    insert(&mut profile, "store-selected", Value::Bool(true));
    insert(&mut root, "profile", Value::Mapping(profile));

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
    insert(&mut root, "sniffer", Value::Mapping(sniffer));

    let mut tun = Mapping::new();
    insert(&mut tun, "enable", Value::Bool(tun_enabled));
    insert(&mut tun, "stack", Value::String("mixed".into()));
    insert(&mut tun, "device", Value::String("CleanWeb".into()));
    insert(&mut tun, "auto-route", Value::Bool(true));
    insert(&mut tun, "auto-detect-interface", Value::Bool(true));
    let mut route_exclude_addresses = vec![
        Value::String("127.0.0.0/8".into()),
        Value::String("::1/128".into()),
    ];
    route_exclude_addresses.extend(
        platform::existing_vpn_route_excludes()
            .into_iter()
            .map(Value::String),
    );
    route_exclude_addresses.extend(dns_upstream_route_excludes(&dns_upstreams));
    insert(
        &mut tun,
        "route-exclude-address",
        Value::Sequence(route_exclude_addresses),
    );
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
    insert(&mut dns, "listen", Value::String("127.0.0.1:53".into()));
    insert(
        &mut dns,
        "enhanced-mode",
        Value::String("redir-host".into()),
    );
    insert(
        &mut dns,
        "default-nameserver",
        Value::Sequence(dns_upstream_values.clone()),
    );
    insert(&mut dns, "respect-rules", Value::Bool(true));
    insert(&mut dns, "use-hosts", Value::Bool(true));
    insert(&mut dns, "use-system-hosts", Value::Bool(true));
    insert(
        &mut dns,
        "nameserver",
        Value::Sequence(vec![Value::String(dns_filter::CLEANWEB_DNS_LISTEN.into())]),
    );
    insert(
        &mut dns,
        "proxy-server-nameserver",
        Value::Sequence(dns_upstream_values.clone()),
    );
    insert(
        &mut dns,
        "direct-nameserver",
        Value::Sequence(vec![Value::String(dns_filter::CLEANWEB_DNS_LISTEN.into())]),
    );
    // 本地域名优先使用保护开启前的系统 DNS，避免丢失内网分流解析。
    let mut ns_policy = Mapping::new();
    insert(
        &mut ns_policy,
        "+.home,+.local,+.lan,+.internal,+.arpa",
        Value::Sequence(dns_upstream_values),
    );
    insert(&mut dns, "nameserver-policy", Value::Mapping(ns_policy));
    insert(&mut root, "dns", Value::Mapping(dns));

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
    let early_network_blocks =
        cleanweb_rules::take_early_network_block_rules(&mut rules, Value::as_str);
    let mut all_rules: Vec<Value> = early_network_blocks;
    all_rules.extend(lan_rules.iter().map(|r| Value::String((*r).into())));
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
    let mut emitted_imported_rules = std::collections::HashSet::new();
    append_imported_rules(
        db,
        &enabled_categories,
        true,
        &mut emitted_imported_rules,
        &mut result,
    )?;
    append_parent_rules(db, "action IN ('block','allow')", &mut result)?;
    if enabled_categories
        .get("category.entertainment")
        .is_some_and(|value| value == "true")
    {
        append_entertainment_rules(&mut result);
    }
    append_imported_rules(
        db,
        &enabled_categories,
        false,
        &mut emitted_imported_rules,
        &mut result,
    )?;
    append_parent_rules(db, "action IN ('proxy','system_route')", &mut result)?;
    append_safe_search_target_routes(db, &enabled_categories, &mut result)?;
    Ok(result)
}

fn append_safe_search_target_routes(
    db: &rusqlite::Connection,
    settings: &std::collections::HashMap<String, String>,
    result: &mut Vec<Value>,
) -> Result<(), String> {
    if !settings
        .get("safe_search_enabled")
        .is_some_and(|value| value == "true")
    {
        return Ok(());
    }
    let mut statement = db
        .prepare(
            "SELECT DISTINCT m.target FROM safe_search_mappings m
             JOIN subscriptions s ON s.id=m.subscription_id
             WHERE s.enabled=1
             ORDER BY m.target",
        )
        .map_err(error)?;
    let targets = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    let mut emitted = result
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<std::collections::HashSet<_>>();
    for target in targets {
        let target = target.trim().trim_end_matches('.').to_ascii_lowercase();
        if target.is_empty() {
            continue;
        }
        let Some(rule) = safe_search_target_route(&target) else {
            continue;
        };
        if emitted.insert(rule.clone()) {
            result.push(Value::String(rule));
        }
    }
    Ok(())
}

fn safe_search_target_route(target: &str) -> Option<String> {
    if let Ok(address) = target.parse::<std::net::IpAddr>() {
        let cidr = if address.is_ipv4() { 32 } else { 128 };
        return mihomo_rule(
            if address.is_ipv4() { "Ip" } else { "Cidr" },
            &format!("{address}/{cidr}"),
            "CleanWeb",
        );
    }
    mihomo_rule("Exact", target, "CleanWeb")
}

fn append_parent_rules(
    db: &rusqlite::Connection,
    action_filter: &str,
    result: &mut Vec<Value>,
) -> Result<(), String> {
    let sql = format!("SELECT kind,pattern,action FROM parent_rules WHERE enabled=1 AND {action_filter} ORDER BY CASE action WHEN 'block' THEN 0 WHEN 'allow' THEN 1 WHEN 'proxy' THEN 2 ELSE 3 END,created_at");
    let mut statement = db.prepare(&sql).map_err(error)?;
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
            "system_route" => "DIRECT",
            _ => "REJECT",
        };
        if let Some(rule) = mihomo_rule(&kind, &pattern, target) {
            result.push(Value::String(rule));
        }
    }
    Ok(())
}

fn append_entertainment_rules(result: &mut Vec<Value>) {
    const ENTERTAINMENT_SUFFIXES: &[&str] = &[
        "douyin.com",
        "douyinpic.com",
        "douyincdn.com",
        "douyinvod.com",
        "iesdouyin.com",
        "snssdk.com",
        "amemv.com",
        "pstatp.com",
        "bytecdn.cn",
        "byteimg.com",
        "bytedance.com",
        "bytedance.net",
        "zijieapi.com",
        "tiktok.com",
        "tiktokv.com",
        "tiktokcdn.com",
        "muscdn.com",
        "byteoversea.com",
        "kuaishou.com",
        "gifshow.com",
        "ksapisrv.com",
        "yximgs.com",
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
        "hdslb.com",
        "biliapi.net",
        "huya.com",
        "msstatic.com",
        "douyu.com",
        "douyucdn.cn",
        "yy.com",
        "huoshan.com",
        "ixigua.com",
        "ixgvideo.com",
        "xiaohongshu.com",
        "xhscdn.com",
        "snapchat.com",
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "roblox.com",
        "rbxcdn.com",
        "steamcommunity.com",
        "steampowered.com",
        "steamstatic.com",
        "epicgames.com",
        "epicgames.dev",
        "discord.com",
        "discord.gg",
        "discordapp.net",
        "twitch.tv",
        "ttvnw.net",
    ];
    const ENTERTAINMENT_KEYWORDS: &[&str] = &[
        "shortvideo",
        "short-video",
        "livestream",
        "live-stream",
        "mobilegame",
        "gamevideo",
    ];
    for suffix in ENTERTAINMENT_SUFFIXES {
        result.push(Value::String(format!("DOMAIN-SUFFIX,{suffix},REJECT")));
    }
    for keyword in ENTERTAINMENT_KEYWORDS {
        result.push(Value::String(format!("DOMAIN-KEYWORD,{keyword},REJECT")));
    }
}

fn append_imported_rules(
    db: &rusqlite::Connection,
    settings: &std::collections::HashMap<String, String>,
    security_only: bool,
    emitted: &mut std::collections::HashSet<String>,
    result: &mut Vec<Value>,
) -> Result<(), String> {
    let comparator = if security_only {
        "IN ('fraud','phishing','malware')"
    } else {
        "NOT IN ('fraud','phishing','malware')"
    };
    let sql = format!(
        "SELECT r.matcher_kind,r.pattern,r.action,r.category
         FROM imported_rules r
         JOIN subscriptions s ON s.id=r.subscription_id
         WHERE s.enabled=1
           AND r.category {comparator}
         ORDER BY s.created_at,r.source_line"
    );
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
        if category == "strict"
            && !settings
                .get("strict_mode_enabled")
                .is_some_and(|value| value == "true")
        {
            continue;
        }
        if settings
            .get(&format!("category.{category}"))
            .is_some_and(|value| value == "false")
        {
            continue;
        }
        let target = match action.as_str() {
            "Allow" => "DIRECT",
            "Proxy" => "CleanWeb",
            _ => "REJECT",
        };
        if let Some(rule) = mihomo_rule(&kind, &pattern, target) {
            if emitted.insert(rule.clone()) {
                result.push(Value::String(rule));
            }
        }
    }
    Ok(())
}

fn mihomo_rule(kind: &str, pattern: &str, target: &str) -> Option<String> {
    Some(match kind {
        "Exact" | "exact" => format!("DOMAIN,{pattern},{target}"),
        "Suffix" | "suffix" => format!("DOMAIN-SUFFIX,{pattern},{target}"),
        "Contains" | "contains" => format!("DOMAIN-KEYWORD,{pattern},{target}"),
        "Wildcard" | "wildcard" => format!("DOMAIN-WILDCARD,{pattern},{target}"),
        "Regex" | "regex" => format!("DOMAIN-REGEX,{pattern},{target}"),
        "Ip" | "ip" | "Cidr" | "cidr" if pattern.contains(':') && target == "DIRECT" => {
            format!("IP-CIDR6,{pattern},{target}")
        }
        "Ip" | "ip" | "Cidr" | "cidr" if pattern.contains(':') => {
            format!("IP-CIDR6,{pattern},{target},no-resolve")
        }
        "Ip" | "ip" | "Cidr" | "cidr" if target == "DIRECT" => {
            format!("IP-CIDR,{pattern},{target}")
        }
        "Ip" | "ip" | "Cidr" | "cidr" => format!("IP-CIDR,{pattern},{target},no-resolve"),
        _ => return None,
    })
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn ensure_binary(app: &AppHandle, runtime: &Path) -> Result<PathBuf, String> {
    let asset = selected_mihomo_asset()?;
    #[cfg(target_os = "windows")]
    let output = runtime.join("mihomo.exe");
    #[cfg(not(target_os = "windows"))]
    let output = runtime.join("mihomo");
    if output.is_file() {
        let bytes = fs::read(&output).map_err(error)?;
        if format!("{:x}", Sha256::digest(&bytes)) == asset.binary_sha256 {
            return Ok(output);
        }
    }
    let resource = app
        .path()
        .resource_dir()
        .map_err(error)?
        .join("resources/mihomo")
        .join(asset.archive);
    if !resource.is_file() {
        return Err(format!("缺少官方 Mihomo 内核资源：{}", resource.display()));
    }
    let bytes = fs::read(&resource).map_err(error)?;
    if format!("{:x}", Sha256::digest(&bytes)) != asset.archive_sha256 {
        return Err("Mihomo 内核校验失败".into());
    }
    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut file = File::create(&output).map_err(error)?;
    io::copy(&mut decoder, &mut file).map_err(error)?;
    file.sync_all().map_err(error)?;
    drop(file);
    let output_bytes = fs::read(&output).map_err(error)?;
    if format!("{:x}", Sha256::digest(&output_bytes)) != asset.binary_sha256 {
        let _ = fs::remove_file(&output);
        return Err("Mihomo 内核解压校验失败".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).map_err(error)?;
    }
    Ok(output)
}

#[cfg(target_os = "macos")]
fn selected_mihomo_asset() -> Result<MihomoAsset, String> {
    Ok(if cfg!(target_arch = "aarch64") {
        MihomoAsset {
            archive: ARM_GZ,
            archive_sha256: ARM_SHA256,
            binary_sha256: ARM_BINARY_SHA256,
        }
    } else {
        MihomoAsset {
            archive: X64_GZ,
            archive_sha256: X64_SHA256,
            binary_sha256: X64_BINARY_SHA256,
        }
    })
}

#[cfg(target_os = "windows")]
fn selected_mihomo_asset() -> Result<MihomoAsset, String> {
    Ok(if cfg!(target_arch = "aarch64") {
        MihomoAsset {
            archive: ARM_GZ,
            archive_sha256: ARM_SHA256,
            binary_sha256: ARM_BINARY_SHA256,
        }
    } else {
        MihomoAsset {
            archive: X64_GZ,
            archive_sha256: X64_SHA256,
            binary_sha256: X64_BINARY_SHA256,
        }
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn ensure_binary(_app: &AppHandle, _runtime: &Path) -> Result<PathBuf, String> {
    Err("Mihomo desktop core is only bundled for macOS and Windows".into())
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

fn configured_dns_upstreams(db: &rusqlite::Connection) -> Result<Vec<String>, String> {
    let value = db
        .query_row(
            "SELECT value FROM settings WHERE key='dns_upstreams'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(error)?;
    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect())
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

fn read_log_since(path: &Path, offset: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

fn emit_runtime_progress(
    app: &AppHandle,
    operation: &str,
    phase: &str,
    percent: u8,
    message: &str,
    components: Vec<CoreComponentStatus>,
) {
    let _ = app.emit(
        RUNTIME_PROGRESS_EVENT,
        RuntimeProgress {
            operation: operation.into(),
            phase: phase.into(),
            percent,
            message: message.into(),
            components,
        },
    );
}

fn emit_runtime_failure(app: &AppHandle, operation: &str, phase: &str, reason: &str) {
    emit_runtime_progress(
        app,
        operation,
        phase,
        100,
        reason.lines().next().unwrap_or("保护启动失败"),
        core_components(false, false, false, false),
    );
}

fn log_startup_phase(
    _app: &AppHandle,
    _operation: &str,
    phase: &str,
    _percent: u8,
    started: Instant,
) {
    eprintln!(
        "CleanWeb protection startup: {phase} after {}ms",
        started.elapsed().as_millis()
    );
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
        || log.contains("batch read packet: bad file descriptor")
}

pub(crate) fn mihomo_data_plane_failed(log: &str) -> bool {
    log.to_ascii_lowercase()
        .contains("batch read packet: bad file descriptor")
}

pub(crate) fn recover_data_plane_failure(app: AppHandle) {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let protection_enabled = {
            let Ok(db) = state.db.lock() else {
                return;
            };
            setting_bool(&db, "protection_enabled").unwrap_or(false)
        };
        if !protection_enabled {
            return;
        }
        if state
            .reload_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Err(reason) = start_inner(&app, &state) {
            eprintln!("CleanWeb failed to recover Mihomo data plane: {reason}");
        }
        state.reload_in_progress.store(false, Ordering::Release);
    });
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
    fn preserves_system_dns_for_split_horizon_resolution() {
        let state = AppState::open(":memory:").unwrap();
        *state.system_dns_servers.lock().unwrap() = vec!["192.168.11.1".into(), "fd00::53".into()];

        let config = build_config(&state, "secret", true).unwrap();
        let yaml: Value = serde_yaml::from_str(&config).unwrap();
        let tun_excludes = yaml
            .get("tun")
            .and_then(|tun| tun.get("route-exclude-address"))
            .and_then(Value::as_sequence)
            .unwrap();
        let default_nameservers = yaml
            .get("dns")
            .and_then(|dns| dns.get("default-nameserver"))
            .and_then(Value::as_sequence)
            .unwrap();

        assert!(tun_excludes.contains(&Value::String("192.168.11.1/32".into())));
        assert!(tun_excludes.contains(&Value::String("fd00::53/128".into())));
        assert_eq!(
            default_nameservers.first().and_then(Value::as_str),
            Some("192.168.11.1:53")
        );
        assert!(default_nameservers.contains(&Value::String("223.5.5.5:53".into())));
    }

    #[test]
    fn keeps_previous_system_dns_when_current_scan_only_sees_cleanweb() {
        assert_eq!(
            select_system_dns_servers(&["192.168.11.1".into()], &[], &[]),
            vec!["192.168.11.1"]
        );
        assert_eq!(
            select_system_dns_servers(&[], &["192.168.11.1".into()], &["10.8.0.1".into()]),
            vec!["192.168.11.1"]
        );
        assert_eq!(
            select_system_dns_servers(&[], &[], &["10.8.0.1".into()]),
            vec!["10.8.0.1"]
        );
    }

    #[test]
    fn generates_locked_redir_host_config_and_filter_rules() {
        let _guard = test_key_env_lock();
        std::env::set_var("CLEANWEB_TEST_PROXY_KEY_B64", STANDARD.encode([4_u8; 32]));
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('r','rule','r','https://x',1)",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('r','1','Suffix','bad.example','Block','pornography',1)",[]).unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('r2','rule','r2','https://x/2',1)",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('r2','1','Suffix','bad.example','Block','pornography',1)",[]).unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('direct-cn','rule','cn','https://x/cn.txt',1)",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('direct-cn','1','Cidr','47.103.0.0/16','Allow','direct',1)",[]).unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,format,enabled) VALUES('safe','rule','safe','https://x/safe.yml','safe-search',1)",[]).unwrap();
            db.execute("INSERT INTO safe_search_mappings(subscription_id,domain,target,source_line) VALUES('safe','www.google.com','forcesafesearch.google.com',1)",[]).unwrap();
            db.execute("INSERT INTO safe_search_mappings(subscription_id,domain,target,source_line) VALUES('safe','family-search.example.com','203.0.113.10',2)",[]).unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('parent-block','block','suffix','baidu.com','custom')",
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
        assert!(config.contains("enhanced-mode: redir-host"));
        assert!(!config.contains("fake-ip-range"));
        assert!(!config.contains("fake-ip-filter"));
        assert!(
            config.contains("DOMAIN-SUFFIX,bad.example,REJECT"),
            "导入的域名拦截必须进入 Mihomo，兼容模式保留系统 DNS 时仍要由 TUN 侧拦截"
        );
        assert!(
            !config.contains("DOMAIN-SUFFIX,baidu.com,DIRECT"),
            "厂商域名直连不应写死在 Mihomo 生成逻辑中"
        );
        assert!(config.contains("name: node-a"));
        assert!(!config.contains("controller_secret"));
        let yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert_eq!(
            yaml.get("unified-delay").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            yaml.get("tcp-concurrent").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            yaml.get("profile")
                .and_then(|profile| profile.get("store-selected"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            yaml.get("profile")
                .and_then(|profile| profile.get("store-fake-ip"))
                .and_then(Value::as_bool),
            None
        );
        assert_eq!(yaml.get("log-level").and_then(Value::as_str), Some("info"));
        assert_eq!(
            yaml.get("find-process-mode").and_then(Value::as_str),
            Some("strict")
        );
        assert!(
            yaml.get("mixed-port").is_none(),
            "TUN 模式不得向其他应用暴露本地代理端口"
        );
        assert!(
            yaml.get("tun")
                .and_then(|tun| tun.get("route-address"))
                .is_none(),
            "redir-host 模式必须让 auto-route 接管默认路由，不能用 route-address 限缩到 DNS 地址"
        );
        let route_excludes = yaml
            .get("tun")
            .and_then(|tun| tun.get("route-exclude-address"))
            .and_then(Value::as_sequence)
            .expect("TUN route excludes");
        assert!(
            route_excludes.contains(&Value::String("127.0.0.0/8".into())),
            "TUN auto-route 必须排除 IPv4 loopback，避免本地隧道和控制面连接被接管"
        );
        assert!(
            route_excludes.contains(&Value::String("::1/128".into())),
            "TUN auto-route 必须排除 IPv6 loopback，避免 localhost 连接被接管"
        );
        assert_eq!(
            yaml.get("dns")
                .and_then(|dns| dns.get("listen"))
                .and_then(Value::as_str),
            Some("127.0.0.1:53"),
            "macOS system DNS is pointed at the local Mihomo DNS listener"
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
                .map(|values| values.contains(&Value::String("223.5.5.5:53".into()))),
            Some(true),
            "代理节点域名和 DNS 上游需要直连 bootstrap DNS，避免启动时解析自举死锁"
        );
        let dns = yaml.get("dns").expect("dns config");
        assert_eq!(
            dns.get("nameserver")
                .and_then(Value::as_sequence)
                .and_then(|values| values.first())
                .and_then(Value::as_str),
            Some(dns_filter::CLEANWEB_DNS_LISTEN)
        );
        assert_eq!(
            dns.get("direct-nameserver")
                .and_then(Value::as_sequence)
                .and_then(|values| values.first())
                .and_then(Value::as_str),
            Some(dns_filter::CLEANWEB_DNS_LISTEN)
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
        let cn_direct = config_rules
            .iter()
            .position(|rule| rule == &Value::String("IP-CIDR,47.103.0.0/16,DIRECT".into()))
            .expect("CN IP direct CIDR rule");
        let fallback_match = config_rules
            .iter()
            .position(|rule| rule.as_str().is_some_and(|text| text.starts_with("MATCH,")))
            .expect("fallback match rule");
        assert!(
            cn_direct < fallback_match,
            "国内公网 IP 直连规则必须先于代理兜底"
        );
        assert!(
            config_rules.contains(&Value::String(
                "DOMAIN,forcesafesearch.google.com,CleanWeb".into()
            )),
            "SafeSearch 订阅里的目标域名必须走代理，避免安全搜索 CNAME 在受限网络中直连失败"
        );
        assert!(
            config_rules.contains(&Value::String(
                "IP-CIDR,203.0.113.10/32,CleanWeb,no-resolve".into()
            )),
            "SafeSearch 订阅里的 IP target 必须按订阅数据通用生成代理路由"
        );
        assert!(yaml.get("dns").and_then(|dns| dns.get("hosts")).is_none());
        std::env::remove_var("CLEANWEB_TEST_PROXY_KEY_B64");
    }

    #[test]
    fn ip_block_rules_precede_builtin_direct_routes() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('block-google-dns','block','Ip','8.8.8.8','custom')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('block-private-lan','block','Cidr','10.0.0.0/8','custom')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('block-private-v6','block','Cidr','fd00::/8','custom')",
                [],
            )
            .unwrap();
        }

        let config = build_config(&state, "secret", true).unwrap();
        let block_google_dns = config
            .find("IP-CIDR,8.8.8.8,REJECT,no-resolve")
            .expect("manual Google DNS IP block");
        let direct_google_dns = config
            .find("IP-CIDR,8.8.8.8/32,DIRECT,no-resolve")
            .expect("built-in Google DNS direct route");
        assert!(
            block_google_dns < direct_google_dns,
            "显式 DNS IP 黑名单必须先于内置 DNS 直连规则"
        );

        let block_lan = config
            .find("IP-CIDR,10.0.0.0/8,REJECT,no-resolve")
            .expect("manual private CIDR block");
        let direct_lan = config
            .find("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
            .expect("built-in private CIDR direct route");
        assert!(
            block_lan < direct_lan,
            "显式内网 CIDR 黑名单必须先于内置内网直连规则"
        );

        let block_ipv6_lan = config
            .find("IP-CIDR6,fd00::/8,REJECT,no-resolve")
            .expect("manual private IPv6 CIDR block");
        let direct_ipv6_lan = config
            .find("IP-CIDR6,fd00::/8,DIRECT,no-resolve")
            .expect("built-in private IPv6 CIDR direct route");
        assert!(
            block_ipv6_lan < direct_ipv6_lan,
            "显式 IPv6 内网 CIDR 黑名单必须先于内置 IPv6 内网直连规则"
        );
    }

    #[test]
    fn lowers_mihomo_overhead_when_access_logging_is_disabled() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE settings SET value='false' WHERE key='access_logging_enabled'",
                [],
            )
            .unwrap();
        }

        let config = build_config(&state, "secret", true).unwrap();
        let yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert_eq!(
            yaml.get("log-level").and_then(Value::as_str),
            Some("warning")
        );
        assert_eq!(
            yaml.get("find-process-mode").and_then(Value::as_str),
            Some("off")
        );
    }

    #[test]
    fn strict_mode_adds_explicit_reject_rules_without_random_domain_heuristics() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO subscriptions(id,kind,name,url,format,category,enabled) VALUES('strict-source','rule','严格规则','https://example.test/strict.txt','clash','strict',1)",
                [],
            )
            .unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('strict-source','strict-1','Suffix','strict.example','Block','strict',1)",[]).unwrap();
        }
        let default_config = build_config(&state, "secret", true).unwrap();
        assert!(!default_config.contains("DOMAIN-SUFFIX,strict.example,REJECT"));
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
        assert!(
            strict_config.contains("DOMAIN-SUFFIX,strict.example,REJECT"),
            "导入的 Exact/Suffix 拦截规则也必须进入 Mihomo，兼容模式保留系统 DNS 时仍要拦截"
        );
        assert!(
            !strict_config.contains("DOMAIN-REGEX,(^|[.])[a-z0-9-]{20}[a-z0-9-]*([.]|$),REJECT"),
            "strict mode must not block broad random-looking domain labels by default"
        );
        for broad_suffix in [
            "vip", "cc", "xyz", "top", "click", "icu", "sbs", "cyou", "monster", "quest", "buzz",
            "fun", "lol", "rest", "cfd", "win", "men", "date", "party", "review", "trade",
            "download", "stream", "gdn", "zip", "mov", "tk", "ml", "ga", "gq", "cf",
        ] {
            assert!(
                !strict_config.contains(&format!("DOMAIN-SUFFIX,{broad_suffix},REJECT")),
                "strict mode must not block broad TLDs that commonly host normal infrastructure"
            );
        }
        assert!(
            !strict_config.contains("DOMAIN-KEYWORD,91,REJECT"),
            "strict mode must not block short numeric fragments"
        );
    }

    #[test]
    fn entertainment_category_blocks_short_video_and_game_rules_only_when_enabled() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled) VALUES('fun','rule','fun','https://x/fun.txt',1)",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('fun','1','Suffix','game.example','Block','entertainment',1)",[]).unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('allow-douyin','allow','Exact','douyin.com','custom')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('proxy-roblox','proxy','Suffix','roblox.com','routing')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO parent_rules(id,action,kind,pattern,category) VALUES('system-route-corp','system_route','Cidr','10.8.0.0/24','routing')",
                [],
            )
            .unwrap();
        }

        let default_config = build_config(&state, "secret", true).unwrap();
        assert!(!default_config.contains("DOMAIN-SUFFIX,douyin.com,REJECT"));
        assert!(!default_config.contains("DOMAIN-SUFFIX,douyinvod.com,REJECT"));
        assert!(!default_config.contains("DOMAIN-SUFFIX,bilivideo.cn,REJECT"));
        assert!(!default_config.contains("DOMAIN-SUFFIX,game.example,REJECT"));

        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE settings SET value='true' WHERE key='category.entertainment'",
                [],
            )
            .unwrap();
        }
        let enabled_config = build_config(&state, "secret", true).unwrap();
        assert!(enabled_config.contains("DOMAIN-SUFFIX,douyin.com,REJECT"));
        assert!(enabled_config.contains("DOMAIN-SUFFIX,douyinvod.com,REJECT"));
        assert!(enabled_config.contains("DOMAIN-SUFFIX,bilivideo.cn,REJECT"));
        assert!(enabled_config.contains("DOMAIN-SUFFIX,roblox.com,REJECT"));
        assert!(
            enabled_config.contains("DOMAIN-SUFFIX,game.example,REJECT"),
            "导入的 Exact/Suffix 拦截规则也必须进入 Mihomo，兼容模式保留系统 DNS 时仍要拦截"
        );
        let allow_douyin = enabled_config.find("DOMAIN,douyin.com,DIRECT").unwrap();
        let reject_douyin = enabled_config
            .find("DOMAIN-SUFFIX,douyin.com,REJECT")
            .unwrap();
        assert!(
            allow_douyin < reject_douyin,
            "手动放行必须先于可选娱乐分类，才能处理误杀"
        );
        let reject_roblox = enabled_config
            .find("DOMAIN-SUFFIX,roblox.com,REJECT")
            .unwrap();
        let proxy_roblox = enabled_config
            .find("DOMAIN-SUFFIX,roblox.com,CleanWeb")
            .unwrap();
        assert!(
            reject_roblox < proxy_roblox,
            "路由规则必须晚于内容过滤，避免走代理绕过拦截"
        );
        let system_route = enabled_config.find("IP-CIDR,10.8.0.0/24,DIRECT").unwrap();
        assert!(
            reject_roblox < system_route,
            "系统路由规则也必须晚于内容过滤，避免绕过拦截"
        );
    }

    #[test]
    fn routing_subscriptions_proxy_download_domains_instead_of_rejecting_them() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO subscriptions(id,kind,name,url,enabled,category) VALUES('route','rule','GFW 域名列表','https://example.test/gfw.txt',1,'routing')",[]).unwrap();
            db.execute("INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line) VALUES('route','1','Suffix','persistent.oaistatic.com','Proxy','routing',1)",[]).unwrap();
        }

        let config = build_config(&state, "secret", true).unwrap();

        assert!(config.contains("DOMAIN-SUFFIX,persistent.oaistatic.com,CleanWeb"));
        assert!(!config.contains("DOMAIN-SUFFIX,persistent.oaistatic.com,REJECT"));
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
    fn rejects_a_live_core_when_tun_fd_breaks_after_startup() {
        let log = r#"{"type":"error","payload":"batch read packet: bad file descriptor"}"#;
        assert!(!tun_startup_ready(log));
        assert!(tun_startup_failed(log));
        assert!(mihomo_data_plane_failed(log));
    }

    #[test]
    fn protection_runtime_requires_all_network_resources() {
        assert!(protection_resources_healthy(true, true, true, true));
        assert!(!protection_resources_healthy(false, true, true, true));
        assert!(!protection_resources_healthy(true, false, true, true));
        assert!(!protection_resources_healthy(true, true, false, true));
        assert!(!protection_resources_healthy(true, true, true, false));
    }

    #[test]
    fn tun_route_excludes_cover_all_dns_upstreams() {
        let values = dns_upstream_route_excludes(&[
            "192.0.2.53:53".into(),
            "198.51.100.53:53".into(),
            "203.0.113.53:53".into(),
            "198.51.100.53:53".into(),
        ]);

        assert_eq!(
            values,
            vec![
                Value::String("192.0.2.53/32".into()),
                Value::String("198.51.100.53/32".into()),
                Value::String("203.0.113.53/32".into()),
            ]
        );
    }

    #[test]
    fn concurrent_protection_start_waits_for_existing_startup() {
        let state = AppState::open(":memory:").unwrap();
        state
            .protection_start_in_progress
            .store(true, Ordering::Release);

        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(150));
                state
                    .protection_start_in_progress
                    .store(false, Ordering::Release);
            });
            let status = wait_for_protection_start(&state).unwrap();
            assert!(!status.running);
        });

        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn runtime_health_failures_report_status_without_stopping_core() {
        let state = AppState::open(":memory:").unwrap();

        assert!(!should_recover_incomplete_protection_state(
            &state, true, true
        ));
        assert!(!should_recover_incomplete_protection_state(
            &state, true, true
        ));
        assert!(!should_recover_incomplete_protection_state(
            &state, true, true
        ));

        reset_protection_health_failures(&state);
        assert!(should_recover_incomplete_protection_state(
            &state, false, true
        ));
        assert!(!should_recover_incomplete_protection_state(
            &state, true, false
        ));
        assert!(!should_recover_incomplete_protection_state(
            &state, true, false
        ));
        assert!(should_recover_incomplete_protection_state(
            &state, true, false
        ));
    }

    #[test]
    fn reports_runtime_component_health() {
        let components = core_components(true, true, true, false);

        assert_eq!(components.len(), 4);
        assert_eq!(components[0].label, "Mihomo 内核");
        assert_eq!(components[0].status, "ready");
        assert_eq!(components[3].label, "本机 DNS 接管");
        assert_eq!(components[3].status, "stopped");
        assert_eq!(components[3].detail, "系统 DNS 未接管");
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
        assert!(!mihomo_data_plane_failed(
            r#"time="2026-08-01T17:58:02+08:00" level=info msg="[TCP] 198.18.0.1:54135 --> example.com:443 match Match() using DIRECT""#
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn official_arm_core_accepts_generated_config() {
        let asset = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/mihomo")
            .join(ARM_GZ);
        assert!(asset.is_file(), "official Mihomo ARM resource is missing");
        let bytes = fs::read(&asset).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), ARM_SHA256);
        let decompressed = {
            let mut decoder = GzDecoder::new(bytes.as_slice());
            let mut decompressed = Vec::new();
            io::copy(&mut decoder, &mut decompressed).unwrap();
            decompressed
        };
        assert_eq!(
            format!("{:x}", Sha256::digest(&decompressed)),
            ARM_BINARY_SHA256
        );
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("mihomo");
        let mut file = File::create(&binary).unwrap();
        file.write_all(&decompressed).unwrap();
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
