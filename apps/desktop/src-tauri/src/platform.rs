//! Cross-platform abstractions for OS-specific operations.
//!
//! All process signaling, OS version detection, and network conflict detection
//! lives here so the rest of CleanWeb compiles on both macOS and Windows. The
//! macOS branches preserve the original behavior; the Windows branches are
//! intentionally minimal and documented where they diverge (see the
//! "fail-open" policy in docs/architecture.md).

use serde::Serialize;
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    time::Duration,
};
use std::{path::Path, process::Command};

#[cfg(target_os = "macos")]
const SYSTEM_RUNTIME_DIR: &str = "/Library/Application Support/CleanWeb";
#[cfg(target_os = "macos")]
const HELPER_LABEL: &str = "app.cleanweb.helper";
#[cfg(target_os = "macos")]
const HELPER_BINARY: &str = "/Library/Application Support/CleanWeb/CleanWebHelper";
#[cfg(target_os = "macos")]
const HELPER_PLIST: &str = "/Library/LaunchDaemons/app.cleanweb.helper.plist";
#[cfg(target_os = "macos")]
const HELPER_SOCKET: &str = "/var/run/cleanweb-helper.sock";
#[cfg(target_os = "macos")]
const DNS_BACKUP_FILE: &str = "/Library/Application Support/CleanWeb/dns-backup.json";
#[cfg(target_os = "macos")]
const CLEANWEB_DNS_SERVER: &str = "127.0.0.1";
#[cfg(target_os = "macos")]
const HELPER_PROTOCOL_VERSION: &str = "2026-08-01-mihomo-binary-hash-helper";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const EXPECTED_MIHOMO_SHA256: &str =
    "55b7286331cb30a54b2564013b02b84a0c280e8b690bd1e5da4b9d4f4ca007ac";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const EXPECTED_MIHOMO_SHA256: &str =
    "35db993895dc2dc7f039cc8e6367c2ef6078d8bc887da2cff12e8cec5307e9d3";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConflicts {
    pub has_conflict: bool,
    pub interfaces: Vec<String>,
    pub vpn_services: Vec<String>,
}

/// Returns the DNS server addresses currently configured by the operating
/// system. On macOS these can be LAN addresses, so the TUN config may add
/// exact routes for them without overriding the whole route table.
pub fn system_dns_servers() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| parse_macos_dns_servers(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    Vec::new()
}

#[cfg(target_os = "macos")]
pub fn default_route_interface() -> Option<String> {
    Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            parse_macos_default_route_interface(&String::from_utf8_lossy(&output.stdout))
        })
}

#[cfg(target_os = "macos")]
fn parse_macos_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in output.lines() {
        let Some((_, value)) = line.trim().split_once(':') else {
            continue;
        };
        if !line.trim_start().starts_with("nameserver[") {
            continue;
        }
        let value = value.trim();
        if value.parse::<std::net::IpAddr>().is_ok()
            && !matches!(value, "127.0.0.1" | "::1" | "198.18.0.1")
            && !values.iter().any(|existing| existing == value)
        {
            values.push(value.to_owned());
        }
    }
    values
}

/// A human-readable operating-system version string.
pub fn os_version() -> String {
    #[cfg(target_os = "macos")]
    if let Some(value) = run_command("sw_vers", &["-productVersion"]) {
        return format!("macOS {}", value.trim());
    }
    #[cfg(target_os = "windows")]
    if let Some(value) = run_command("cmd", &["/c", "ver"]) {
        let trimmed = value.trim();
        // Typical output: "Microsoft Windows [Version 10.0.22631.3737]"
        if let Some(rest) = trimmed.strip_prefix("Microsoft Windows [Version ") {
            if let Some(rest) = rest.strip_suffix(']') {
                return format!("Windows {rest}");
            }
        }
        return format!("Windows ({trimmed})");
    }
    std::env::consts::OS.to_string()
}

/// Detects other VPN/TUN interfaces and services that would conflict with
/// CleanWeb's own TUN takeover.
pub fn detect_network_conflicts() -> NetworkConflicts {
    #[cfg(target_os = "macos")]
    {
        detect_macos_conflicts()
    }
    #[cfg(target_os = "windows")]
    {
        // TODO(Windows): detect active VPN/TUN via WFP or Get-NetAdapter in a
        // later batch. Returning an empty conflict set keeps V1 fail-open
        // behavior on Windows; the macOS path is the verified one for now.
        NetworkConflicts {
            has_conflict: false,
            interfaces: Vec::new(),
            vpn_services: Vec::new(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        NetworkConflicts {
            has_conflict: false,
            interfaces: Vec::new(),
            vpn_services: Vec::new(),
        }
    }
}

/// Returns true when a process with the given PID is currently running.
pub fn pid_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `kill` with signal 0 performs no signal delivery; it only
        // checks liveness and permissions.
        let result = unsafe { libc::kill(pid as i32, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .is_some_and(|s| s.contains(&pid.to_string()))
    }
}

/// Rejects stale PID files that now point at an unrelated process.
pub fn cleanweb_mihomo_running(pid: u32) -> bool {
    if !pid_running(pid) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        run_command("/bin/ps", &["-p", &pid.to_string(), "-o", "command="])
            .is_some_and(|command| is_cleanweb_mihomo_command(&command))
    }
    #[cfg(not(target_os = "macos"))]
    true
}

/// Terminates root-owned CleanWeb Mihomo processes that may have outlived the
/// user-scoped PID file.
pub fn terminate_cleanweb_mihomo_processes() {
    #[cfg(target_os = "macos")]
    {
        let pids = cleanweb_mihomo_pids();
        for pid in &pids {
            terminate_process(*pid);
        }
        for _ in 0..20 {
            if pids.iter().all(|pid| !cleanweb_mihomo_running(*pid)) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        for pid in pids {
            if cleanweb_mihomo_running(pid) {
                kill_process(pid);
            }
        }
    }
}

/// Politely requests a process to terminate (SIGTERM on Unix).
pub fn terminate_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_process(pid, libc::SIGTERM)
    }
    #[cfg(not(unix))]
    {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// Forcefully kills a process (SIGKILL on Unix).
pub fn kill_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_process(pid, libc::SIGKILL)
    }
    #[cfg(not(unix))]
    {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()
            .is_ok_and(|s| s.success())
    }
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: i32) -> bool {
    if unsafe { libc::kill(pid as i32, signal) } == 0 {
        return true;
    }
    #[cfg(target_os = "macos")]
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        return run_admin_shell(&format!("/bin/kill -{signal} {pid}")).is_ok();
    }
    false
}

/// Installs a root-owned copy of the validated core and its generated config,
/// then starts it with the privileges required to create a macOS TUN device.
#[cfg(target_os = "macos")]
pub fn start_mihomo_privileged(binary: &Path, config: &Path) -> Result<(u32, PathBuf), String> {
    ensure_privileged_helper()?;
    let request = HelperRequest::Start {
        binary: binary.display().to_string(),
        config: config.display().to_string(),
    };
    let response = call_helper(&request)?;
    if !response.ok {
        return Err(response
            .message
            .unwrap_or_else(|| "CleanWeb 特权服务启动 Mihomo 失败".into()));
    }
    let pid = response.pid.ok_or("CleanWeb 特权服务未返回 Mihomo PID")?;
    Ok((
        pid,
        PathBuf::from(
            response
                .log
                .unwrap_or_else(|| format!("{SYSTEM_RUNTIME_DIR}/mihomo.log")),
        ),
    ))
}

#[cfg(target_os = "macos")]
pub fn stop_mihomo_privileged() -> Result<(), String> {
    ensure_privileged_helper()?;
    let response = call_helper(&HelperRequest::Stop)?;
    if response.ok {
        Ok(())
    } else {
        Err(response
            .message
            .unwrap_or_else(|| "CleanWeb 特权服务关闭 Mihomo 失败".into()))
    }
}

pub fn truncate_mihomo_log(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if path == Path::new(&format!("{SYSTEM_RUNTIME_DIR}/mihomo.log")) {
        ensure_privileged_helper()?;
        let response = call_helper(&HelperRequest::TruncateMihomoLog)?;
        return if response.ok {
            Ok(())
        } else {
            Err(response
                .message
                .unwrap_or_else(|| "CleanWeb 特权服务截断 Mihomo 日志失败".into()))
        };
    }
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_len(0))
        .map_err(|value| format!("无法截断 Mihomo 日志：{value}"))
}

#[cfg(target_os = "macos")]
pub fn run_privileged_helper() -> Result<(), String> {
    let _ = fs::remove_file(HELPER_SOCKET);
    let listener = UnixListener::bind(HELPER_SOCKET)
        .map_err(|value| format!("无法创建 CleanWeb 特权服务 socket：{value}"))?;
    fs::set_permissions(HELPER_SOCKET, fs::Permissions::from_mode(0o666))
        .map_err(|value| format!("无法设置 CleanWeb 特权服务 socket 权限：{value}"))?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(reason) = handle_helper_client(stream) {
                    write_helper_log(&format!("client error: {reason}"));
                }
            }
            Err(reason) => write_helper_log(&format!("accept error: {reason}")),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn handle_helper_client(mut stream: UnixStream) -> Result<(), String> {
    let peer_uid = helper_peer_uid(&stream)?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|value| format!("无法读取特权服务请求：{value}"))?,
        );
        reader
            .read_line(&mut line)
            .map_err(|value| format!("无法读取特权服务请求：{value}"))?;
    }
    let request: HelperRequest = serde_json::from_str(&line)
        .map_err(|value| format!("CleanWeb 特权服务请求格式无效：{value}"))?;
    let response = match request {
        HelperRequest::Ping => HelperResponse::ok(),
        HelperRequest::Version => HelperResponse {
            ok: true,
            message: Some(HELPER_PROTOCOL_VERSION.into()),
            pid: None,
            log: None,
        },
        HelperRequest::Stop => {
            match validate_helper_peer_uid(peer_uid).and_then(|_| helper_stop_mihomo()) {
                Ok(()) => HelperResponse::ok(),
                Err(reason) => HelperResponse::err(reason),
            }
        }
        HelperRequest::TruncateMihomoLog => {
            match validate_helper_peer_uid(peer_uid).and_then(|_| helper_truncate_mihomo_log()) {
                Ok(()) => HelperResponse::ok(),
                Err(reason) => HelperResponse::err(reason),
            }
        }
        HelperRequest::Start { binary, config } => match validate_helper_peer_uid(peer_uid)
            .and_then(|_| helper_start_mihomo(&binary, &config, peer_uid))
        {
            Ok((pid, log)) => HelperResponse {
                ok: true,
                message: None,
                pid: Some(pid),
                log: Some(log.display().to_string()),
            },
            Err(reason) => HelperResponse::err(reason),
        },
    };
    let body = serde_json::to_string(&response).map_err(|value| value.to_string())?;
    stream
        .write_all(format!("{body}\n").as_bytes())
        .map_err(|value| format!("无法写入特权服务响应：{value}"))
}

#[cfg(target_os = "macos")]
fn helper_peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid reads credentials for this connected Unix socket and
    // writes them into valid uid/gid output pointers.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(format!(
            "无法验证 CleanWeb 特权服务调用者：{}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "macos")]
fn validate_helper_peer_uid(peer_uid: u32) -> Result<(), String> {
    let console_uid = fs::metadata("/dev/console")
        .map_err(|value| format!("无法验证当前控制台用户：{value}"))?
        .uid();
    if peer_uid == console_uid {
        Ok(())
    } else {
        Err("CleanWeb 特权服务拒绝非当前登录用户的请求".into())
    }
}

#[cfg(target_os = "macos")]
fn helper_truncate_mihomo_log() -> Result<(), String> {
    let log = Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.log");
    fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .and_then(|file| file.set_len(0))
        .map_err(|value| format!("无法截断 Mihomo 日志：{value}"))
}

#[cfg(target_os = "macos")]
fn helper_start_mihomo(
    binary: &str,
    config: &str,
    peer_uid: u32,
) -> Result<(u32, PathBuf), String> {
    let source_binary = validate_user_mihomo_path(Path::new(binary), peer_uid)?;
    let source_config = validate_user_config_path(Path::new(config), peer_uid)?;
    let system_dir = PathBuf::from(SYSTEM_RUNTIME_DIR);
    let installed_binary = system_dir.join("mihomo");
    let installed_config = system_dir.join("config.yaml");
    let log = system_dir.join("mihomo.log");
    let safe_paths = source_config.parent().ok_or("无法定位 CleanWeb 配置目录")?;

    helper_stop_mihomo()?;
    fs::create_dir_all(&system_dir).map_err(|value| format!("无法创建系统运行目录：{value}"))?;
    fs::copy(&source_binary, &installed_binary)
        .map_err(|value| format!("无法安装 Mihomo 内核：{value}"))?;
    fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o700))
        .map_err(|value| format!("无法设置 Mihomo 权限：{value}"))?;
    fs::copy(&source_config, &installed_config)
        .map_err(|value| format!("无法安装 Mihomo 配置：{value}"))?;
    fs::set_permissions(&installed_config, fs::Permissions::from_mode(0o600))
        .map_err(|value| format!("无法设置 Mihomo 配置权限：{value}"))?;
    File::create(&log).map_err(|value| format!("无法创建 Mihomo 日志：{value}"))?;
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644))
        .map_err(|value| format!("无法设置 Mihomo 日志权限：{value}"))?;

    let stdout = fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .map_err(|value| format!("无法打开 Mihomo 日志：{value}"))?;
    let stderr = stdout
        .try_clone()
        .map_err(|value| format!("无法复制 Mihomo 日志句柄：{value}"))?;
    let mut child = Command::new(&installed_binary)
        .arg("-d")
        .arg(&system_dir)
        .arg("-f")
        .arg(&installed_config)
        .env("SAFE_PATHS", safe_paths)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|value| format!("无法启动 Mihomo：{value}"))?;
    let pid = child.id();
    if let Err(reason) = backup_and_set_macos_dns() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(reason);
    }
    std::mem::forget(child);
    Ok((pid, log))
}

#[cfg(target_os = "macos")]
fn helper_stop_mihomo() -> Result<(), String> {
    let pids = cleanweb_mihomo_pids();
    for pid in &pids {
        let _ = unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
    }
    for _ in 0..20 {
        if pids.iter().all(|pid| !pid_running(*pid)) {
            restore_macos_dns()?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for pid in &pids {
        if pid_running(*pid) {
            let _ = unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
    }
    restore_macos_dns()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn backup_and_set_macos_dns() -> Result<(), String> {
    if !Path::new(DNS_BACKUP_FILE).exists() {
        let backup = collect_macos_dns_backup()?;
        let body = serde_json::to_string_pretty(&backup)
            .map_err(|value| format!("无法序列化 DNS 备份：{value}"))?;
        fs::write(DNS_BACKUP_FILE, body).map_err(|value| format!("无法写入 DNS 备份：{value}"))?;
        fs::set_permissions(DNS_BACKUP_FILE, fs::Permissions::from_mode(0o600))
            .map_err(|value| format!("无法设置 DNS 备份权限：{value}"))?;
    }
    for service in list_macos_network_services()? {
        let output = Command::new("/usr/sbin/networksetup")
            .args(["-setdnsservers", &service, CLEANWEB_DNS_SERVER])
            .output()
            .map_err(|value| format!("无法设置系统 DNS：{value}"))?;
        if !output.status.success() {
            return Err(format!(
                "无法设置网络服务 {service} 的 DNS：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_macos_dns() -> Result<(), String> {
    let path = Path::new(DNS_BACKUP_FILE);
    if !path.exists() {
        return Ok(());
    }
    let body = fs::read_to_string(path).map_err(|value| format!("无法读取 DNS 备份：{value}"))?;
    let backup: DnsBackup =
        serde_json::from_str(&body).map_err(|value| format!("DNS 备份格式无效：{value}"))?;
    for service in backup.services {
        let mut command = Command::new("/usr/sbin/networksetup");
        command.arg("-setdnsservers").arg(&service.name);
        if service.automatic {
            command.arg("Empty");
        } else {
            command.args(&service.servers);
        }
        let output = command
            .output()
            .map_err(|value| format!("无法恢复系统 DNS：{value}"))?;
        if !output.status.success() {
            return Err(format!(
                "无法恢复网络服务 {} 的 DNS：{}",
                service.name,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    fs::remove_file(path).map_err(|value| format!("无法删除 DNS 备份：{value}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn collect_macos_dns_backup() -> Result<DnsBackup, String> {
    let mut services = Vec::new();
    for service in list_macos_network_services()? {
        let output = Command::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", &service])
            .output()
            .map_err(|value| format!("无法读取网络服务 DNS：{value}"))?;
        if !output.status.success() {
            return Err(format!(
                "无法读取网络服务 {service} 的 DNS：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        services.push(parse_macos_dns_backup_service(
            &service,
            &String::from_utf8_lossy(&output.stdout),
        ));
    }
    Ok(DnsBackup { services })
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> Result<Vec<String>, String> {
    let output = Command::new("/usr/sbin/networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|value| format!("无法读取网络服务列表：{value}"))?;
    if !output.status.success() {
        return Err(format!(
            "无法读取网络服务列表：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_macos_network_services(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "macos")]
fn parse_macos_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(ToOwned::to_owned)
        .filter(|line| !line.is_empty())
        .collect()
}

#[cfg(target_os = "macos")]
fn parse_macos_dns_backup_service(name: &str, output: &str) -> DnsServiceBackup {
    let servers: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
        .map(ToOwned::to_owned)
        .collect();
    DnsServiceBackup {
        name: name.to_owned(),
        automatic: servers.is_empty(),
        servers,
    }
}

#[cfg(target_os = "macos")]
fn ensure_privileged_helper() -> Result<(), String> {
    if helper_protocol_is_current() {
        return Ok(());
    }
    install_privileged_helper()?;
    for _ in 0..30 {
        if helper_protocol_is_current() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("CleanWeb 特权服务安装后未就绪".into())
}

#[cfg(target_os = "macos")]
fn helper_protocol_is_current() -> bool {
    call_helper(&HelperRequest::Version).is_ok_and(|response| {
        response.ok && response.message.as_deref() == Some(HELPER_PROTOCOL_VERSION)
    })
}

#[cfg(target_os = "macos")]
fn install_privileged_helper() -> Result<(), String> {
    let helper_source = prepare_helper_install_source()?;
    let plist = helper_plist();
    let temp_plist = helper_source.with_file_name("app.cleanweb.helper.plist");
    fs::write(&temp_plist, plist).map_err(|value| format!("无法写入特权服务配置：{value}"))?;
    let command = format!(
        "set -e; /bin/mkdir -p {dir}; /usr/bin/install -o root -g wheel -m 755 {source} {helper}; /usr/bin/install -o root -g wheel -m 644 {plist_source} {plist}; /bin/launchctl bootout system/{label} >/dev/null 2>&1 || true; /bin/launchctl bootstrap system {plist}; /bin/launchctl kickstart -k system/{label}",
        dir = shell_quote(Path::new(SYSTEM_RUNTIME_DIR)),
        source = shell_quote(&helper_source),
        helper = shell_quote(Path::new(HELPER_BINARY)),
        plist_source = shell_quote(&temp_plist),
        plist = shell_quote(Path::new(HELPER_PLIST)),
        label = HELPER_LABEL,
    );
    run_admin_shell(&command).map(|_| ())
}

#[cfg(target_os = "macos")]
fn prepare_helper_install_source() -> Result<PathBuf, String> {
    let executable =
        std::env::current_exe().map_err(|value| format!("无法定位 CleanWeb：{value}"))?;
    let directory = std::env::temp_dir().join("cleanweb-helper-install");
    fs::create_dir_all(&directory).map_err(|value| format!("无法创建 helper 安装缓存：{value}"))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
        .map_err(|value| format!("无法设置 helper 安装缓存权限：{value}"))?;
    let helper_source = directory.join("CleanWebHelper");
    fs::copy(&executable, &helper_source)
        .map_err(|value| format!("无法准备 helper 安装源：{value}"))?;
    fs::set_permissions(&helper_source, fs::Permissions::from_mode(0o755))
        .map_err(|value| format!("无法设置 helper 安装源权限：{value}"))?;
    Ok(helper_source)
}

#[cfg(target_os = "macos")]
fn helper_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{helper}</string><string>--cleanweb-privileged-helper</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>StandardOutPath</key><string>{dir}/helper.log</string><key>StandardErrorPath</key><string>{dir}/helper.log</string></dict></plist>\n",
        label = HELPER_LABEL,
        helper = xml_escape(HELPER_BINARY),
        dir = xml_escape(SYSTEM_RUNTIME_DIR),
    )
}

#[cfg(target_os = "macos")]
fn call_helper(request: &HelperRequest) -> Result<HelperResponse, String> {
    let mut stream = UnixStream::connect(HELPER_SOCKET)
        .map_err(|value| format!("无法连接 CleanWeb 特权服务：{value}"))?;
    let body = serde_json::to_string(request).map_err(|value| value.to_string())?;
    stream
        .write_all(format!("{body}\n").as_bytes())
        .map_err(|value| format!("无法发送特权服务请求：{value}"))?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|value| format!("无法读取特权服务响应：{value}"))?;
    serde_json::from_str(&response).map_err(|value| format!("特权服务响应无效：{value}"))
}

#[cfg(target_os = "macos")]
fn validate_user_mihomo_path(path: &Path, peer_uid: u32) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|value| format!("无法验证 Mihomo 路径：{value}"))?;
    if canonical.file_name().and_then(|value| value.to_str()) != Some("mihomo") {
        return Err("特权服务拒绝非 Mihomo 内核路径".into());
    }
    validate_cleanweb_user_runtime_path(&canonical)?;
    validate_peer_owned_helper_file(&canonical, peer_uid)?;
    validate_mihomo_binary_hash(&canonical)?;
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn validate_user_config_path(path: &Path, peer_uid: u32) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|value| format!("无法验证 Mihomo 配置路径：{value}"))?;
    if canonical.file_name().and_then(|value| value.to_str()) != Some("config.yaml") {
        return Err("特权服务拒绝非 CleanWeb 配置路径".into());
    }
    validate_cleanweb_user_runtime_path(&canonical)?;
    validate_peer_owned_helper_file(&canonical, peer_uid)?;
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn validate_peer_owned_helper_file(path: &Path, peer_uid: u32) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|value| format!("无法读取 CleanWeb 文件权限：{value}"))?;
    if metadata.uid() != peer_uid {
        return Err("特权服务拒绝非调用用户拥有的 CleanWeb 文件".into());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err("特权服务拒绝 group/world 可写的 CleanWeb 文件".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_mihomo_binary_hash(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|value| format!("无法读取 Mihomo 内核：{value}"))?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest == EXPECTED_MIHOMO_SHA256 {
        Ok(())
    } else {
        Err("特权服务拒绝未随 CleanWeb 分发的 Mihomo 内核".into())
    }
}

#[cfg(target_os = "macos")]
fn validate_cleanweb_user_runtime_path(path: &Path) -> Result<(), String> {
    let value = path.to_string_lossy();
    if value.starts_with("/Users/")
        && value.contains("/Library/Application Support/")
        && value.contains("/mihomo/")
    {
        Ok(())
    } else {
        Err("特权服务拒绝 CleanWeb 数据目录外的路径".into())
    }
}

#[cfg(target_os = "macos")]
fn write_helper_log(message: &str) {
    let _ = fs::create_dir_all(SYSTEM_RUNTIME_DIR);
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{SYSTEM_RUNTIME_DIR}/helper.log"))
    {
        let _ = writeln!(file, "{message}");
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum HelperRequest {
    Ping,
    Version,
    Start { binary: String, config: String },
    Stop,
    TruncateMihomoLog,
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize, serde::Serialize)]
struct HelperResponse {
    ok: bool,
    message: Option<String>,
    pid: Option<u32>,
    log: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize, serde::Serialize)]
struct DnsBackup {
    services: Vec<DnsServiceBackup>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct DnsServiceBackup {
    name: String,
    automatic: bool,
    servers: Vec<String>,
}

#[cfg(target_os = "macos")]
impl HelperResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            message: None,
            pid: None,
            log: None,
        }
    }

    fn err(message: String) -> Self {
        Self {
            ok: false,
            message: Some(message),
            pid: None,
            log: None,
        }
    }
}

#[cfg(target_os = "macos")]
fn run_admin_shell(command: &str) -> Result<String, String> {
    let output = Command::new("/usr/bin/osascript")
        .current_dir("/")
        .args([
            "-e",
            "on run argv",
            "-e",
            "return do shell script (item 1 of argv) with administrator privileges",
            "-e",
            "end run",
            "--",
            command,
        ])
        .output()
        .map_err(|value| format!("无法请求 macOS 管理员权限：{value}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(
            if message.contains("User canceled") || message.contains("-128") {
                "已取消管理员授权，CleanWeb 未开启保护".into()
            } else {
                format!("macOS 管理员授权失败：{message}")
            },
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(target_os = "macos")]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
pub fn install_login_agent(executable: &Path) -> Result<(), String> {
    let home = std::env::var_os("HOME").ok_or("无法定位用户目录")?;
    let directory = PathBuf::from(home).join("Library/LaunchAgents");
    fs::create_dir_all(&directory).map_err(|value| format!("无法创建登录启动目录：{value}"))?;
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>app.cleanweb.desktop</string><key>ProgramArguments</key><array><string>{}</string><string>--background</string></array><key>RunAtLoad</key><true/></dict></plist>\n",
        xml_escape(&executable.to_string_lossy())
    );
    let path = directory.join("app.cleanweb.desktop.plist");
    let temporary = path.with_extension("plist.tmp");
    fs::write(&temporary, plist).map_err(|value| format!("无法写入登录启动项：{value}"))?;
    fs::rename(temporary, path).map_err(|value| format!("无法安装登录启动项：{value}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn detect_macos_conflicts() -> NetworkConflicts {
    let interfaces: Vec<String> = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
        .map(|value| {
            value
                .lines()
                .filter_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
                .filter(|name| {
                    name.starts_with("utun") || name.starts_with("ppp") || name.starts_with("ipsec")
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let vpn_services: Vec<String> = Command::new("scutil")
        .args(["--nc", "list"])
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
        .map(|value| {
            value
                .lines()
                .filter(|line| line.contains("(Connected)"))
                .map(|line| line.trim().to_owned())
                .collect()
        })
        .unwrap_or_default();
    NetworkConflicts {
        has_conflict: !interfaces.is_empty() || !vpn_services.is_empty(),
        interfaces,
        vpn_services,
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_command(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
}

#[cfg(target_os = "macos")]
fn cleanweb_mihomo_pids() -> Vec<u32> {
    run_command("/bin/ps", &["-axo", "pid=,command="])
        .map(|output| {
            output
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim_start();
                    let (pid, command) = trimmed.split_once(char::is_whitespace)?;
                    if is_cleanweb_mihomo_command(command) {
                        pid.parse().ok()
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn is_cleanweb_mihomo_command(command: &str) -> bool {
    let expected = format!("{SYSTEM_RUNTIME_DIR}/mihomo");
    command.contains(&expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_is_nonempty() {
        assert!(!os_version().is_empty());
    }

    #[test]
    fn conflict_shape_is_consistent() {
        let value = detect_network_conflicts();
        assert_eq!(
            value.has_conflict,
            !value.interfaces.is_empty() || !value.vpn_services.is_empty()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_unique_macos_dns_servers() {
        let output = "resolver #1\n  nameserver[0] : 10.195.85.120\n  nameserver[1] : 240e:479::19\nresolver #2\n  nameserver[0] : 10.195.85.120\n";
        assert_eq!(
            parse_macos_dns_servers(output),
            vec!["10.195.85.120", "240e:479::19"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_default_route_interface() {
        let output = "   route to: default\n      gateway: 10.75.80.184\n    interface: en0\n";
        assert_eq!(
            parse_macos_default_route_interface(output),
            Some("en0".into())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_network_services_without_warning_or_disabled_marker() {
        let output = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB 10/100/1000 LAN\nThunderbolt Bridge\n";
        assert_eq!(
            parse_macos_network_services(output),
            vec!["Wi-Fi", "Thunderbolt Bridge"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_manual_and_automatic_macos_dns_backup_services() {
        assert_eq!(
            parse_macos_dns_backup_service("Wi-Fi", "114.114.114.114\n8.8.8.8\n"),
            DnsServiceBackup {
                name: "Wi-Fi".into(),
                automatic: false,
                servers: vec!["114.114.114.114".into(), "8.8.8.8".into()],
            }
        );
        assert_eq!(
            parse_macos_dns_backup_service(
                "Ethernet",
                "There aren't any DNS Servers set on Ethernet.\n"
            ),
            DnsServiceBackup {
                name: "Ethernet".into(),
                automatic: true,
                servers: Vec::new(),
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn helper_rejects_paths_outside_cleanweb_user_runtime() {
        assert!(validate_cleanweb_user_runtime_path(Path::new(
            "/Users/alice/Library/Application Support/app.cleanweb.desktop/mihomo/config.yaml"
        ))
        .is_ok());
        assert!(
            validate_cleanweb_user_runtime_path(Path::new("/Users/alice/Desktop/config.yaml"))
                .is_err()
        );
        assert!(validate_cleanweb_user_runtime_path(Path::new(
            "/Library/Application Support/CleanWeb/config.yaml"
        ))
        .is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn helper_accepts_official_decompressed_mihomo_binary_hash() {
        use flate2::read::GzDecoder;
        use std::io;

        #[cfg(target_arch = "aarch64")]
        const ASSET: &str = "mihomo-darwin-arm64-v1.19.28.gz";
        #[cfg(target_arch = "x86_64")]
        const ASSET: &str = "mihomo-darwin-amd64-compatible-v1.19.28.gz";

        let resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/mihomo")
            .join(ASSET);
        let bytes = fs::read(resource).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("mihomo");
        let mut decoder = GzDecoder::new(bytes.as_slice());
        let mut file = File::create(&binary).unwrap();
        io::copy(&mut decoder, &mut file).unwrap();

        validate_mihomo_binary_hash(&binary).unwrap();
    }
}
