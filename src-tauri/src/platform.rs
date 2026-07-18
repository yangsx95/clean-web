//! Cross-platform abstractions for OS-specific operations.
//!
//! All process signaling, OS version detection, and network conflict detection
//! lives here so the rest of CleanWeb compiles on both macOS and Windows. The
//! macOS branches preserve the original behavior; the Windows branches are
//! intentionally minimal and documented where they diverge (see the
//! "fail-open" policy in docs/architecture.md).

use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "macos")]
use crate::privileged_service;

#[cfg(target_os = "macos")]
const SYSTEM_RUNTIME_DIR: &str = "/Library/Application Support/CleanWeb";

pub fn mihomo_log_path(data_dir: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = data_dir;
        PathBuf::from(SYSTEM_RUNTIME_DIR).join("mihomo.log")
    }
    #[cfg(not(target_os = "macos"))]
    {
        data_dir.join("mihomo/mihomo.log")
    }
}

pub fn xray_access_log_path(data_dir: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = data_dir;
        PathBuf::from(SYSTEM_RUNTIME_DIR).join("xray-access.log")
    }
    #[cfg(not(target_os = "macos"))]
    {
        data_dir.join("xray/xray-access.log")
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConflicts {
    pub has_conflict: bool,
    pub interfaces: Vec<String>,
    pub vpn_services: Vec<String>,
    pub system_proxies: Vec<String>,
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
            system_proxies: Vec::new(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        NetworkConflicts {
            has_conflict: false,
            interfaces: Vec::new(),
            vpn_services: Vec::new(),
            system_proxies: Vec::new(),
        }
    }
}

/// Selects an unused explicit TUN name for Xray. Xray 26.3.27 rejects the
/// documented `utunN` placeholder on macOS, so the control plane must resolve
/// it before validation and startup.
pub fn xray_tun_name() -> String {
    #[cfg(target_os = "macos")]
    {
        let interfaces = run_command("/sbin/ifconfig", &["-l"]).unwrap_or_default();
        first_available_utun(&interfaces)
    }
    #[cfg(target_os = "windows")]
    {
        "CleanWeb".into()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "cleanweb0".into()
    }
}

pub fn default_network_interface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        route_interface("default")
    }
    #[cfg(not(target_os = "macos"))]
    None
}

pub fn public_route_uses(interface: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        route_interface("8.8.8.8").as_deref() == Some(interface)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = interface;
        true
    }
}

/// Returns true only when the active macOS resolver is CleanWeb's loopback
/// listener. A running TUN alone is not sufficient: local-subnet DNS can
/// otherwise bypass the tunnel and defeat SafeSearch.
pub fn system_dns_uses_cleanweb() -> bool {
    #[cfg(target_os = "macos")]
    {
        Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .is_some_and(|output| dns_output_uses_loopback(&output))
    }
    #[cfg(not(target_os = "macos"))]
    true
}

#[cfg(target_os = "macos")]
fn dns_output_uses_loopback(output: &str) -> bool {
    // Resolver #1 is the default, unscoped resolver used for ordinary domain
    // lookups. Scoped/mDNS entries later in the output must not make a stale
    // router resolver appear healthy.
    output
        .split("resolver #")
        .find(|resolver| resolver.trim_start().starts_with('1'))
        .is_some_and(|resolver| {
            resolver.lines().any(|line| {
                line.trim()
                    .strip_prefix("nameserver[")
                    .and_then(|line| line.split_once(" : "))
                    .is_some_and(|(_, address)| address.trim() == "127.0.0.1")
            })
        })
}

#[cfg(target_os = "macos")]
fn route_interface(destination: &str) -> Option<String> {
    Command::new("/sbin/route")
        .args(["-n", "get", destination])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| {
            output.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("interface:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
        })
}

#[cfg(target_os = "macos")]
fn first_available_utun(interfaces: &str) -> String {
    let used = interfaces
        .split_whitespace()
        .collect::<std::collections::HashSet<_>>();
    (200..=1024)
        .map(|index| format!("utun{index}"))
        .find(|name| !used.contains(name.as_str()))
        .unwrap_or_else(|| "utun1024".into())
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
        let expected = format!("{SYSTEM_RUNTIME_DIR}/mihomo");
        run_command("/bin/ps", &["-p", &pid.to_string(), "-o", "command="])
            .is_some_and(|command| command.contains(&expected))
    }
    #[cfg(not(target_os = "macos"))]
    true
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
        return ensure_privileged_service()
            .and_then(|()| privileged_service::stop(Some(pid)))
            .is_ok();
    }
    false
}

/// Installs a root-owned copy of the validated core and its generated config,
/// then starts it with the privileges required to create a macOS TUN device.
#[cfg(target_os = "macos")]
pub fn start_mihomo_privileged(binary: &Path, config: &Path) -> Result<(u32, PathBuf), String> {
    ensure_privileged_service()?;
    let pid = privileged_service::start(binary, config)?;
    Ok((pid, PathBuf::from(SYSTEM_RUNTIME_DIR).join("mihomo.log")))
}

#[cfg(target_os = "macos")]
pub fn start_network_stack_privileged(
    binary: &Path,
    config: &Path,
    xray_binary: &Path,
    xray_config: &Path,
) -> Result<(u32, PathBuf), String> {
    ensure_privileged_service()?;
    let pid = privileged_service::start_stack(binary, config, xray_binary, xray_config)?;
    Ok((pid, PathBuf::from(SYSTEM_RUNTIME_DIR).join("xray.log")))
}

/// Installs the root LaunchDaemon once. Normal start/stop operations then use
/// the narrow Unix-socket protocol and do not show another password prompt.
#[cfg(target_os = "macos")]
fn ensure_privileged_service() -> Result<(), String> {
    if privileged_service::ping() {
        return Ok(());
    }
    let executable = std::env::current_exe().map_err(|value| value.to_string())?;
    let staging = stage_privileged_service_files(&executable)?;
    let temporary_plist = staging.join("app.cleanweb.privileged-service.plist");
    let staged_executable = staging.join("app.cleanweb.privileged-service");
    let helper = Path::new("/Library/PrivilegedHelperTools/app.cleanweb.privileged-service");
    let installed_plist = Path::new("/Library/LaunchDaemons/app.cleanweb.privileged-service.plist");
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{helper}</string><string>--privileged-service</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Interactive</string></dict></plist>\n",
        label = privileged_service::SERVICE_LABEL,
        helper = xml_escape(&helper.to_string_lossy()),
    );
    fs::write(&temporary_plist, plist).map_err(|value| value.to_string())?;
    let command = format!(
        "{{ /bin/launchctl bootout system/{label} >/dev/null 2>&1 || true; }} && /bin/mkdir -p /Library/PrivilegedHelperTools && /usr/bin/install -o root -g wheel -m 755 {source} {helper} && /usr/bin/install -o root -g wheel -m 644 {source_plist} {plist} && /bin/launchctl bootstrap system {plist}",
        label = privileged_service::SERVICE_LABEL,
        source = shell_quote(&staged_executable),
        helper = shell_quote(helper),
        source_plist = shell_quote(&temporary_plist),
        plist = shell_quote(installed_plist),
    );
    let result = run_admin_shell(&command);
    let _ = fs::remove_dir_all(staging);
    result?;
    for _ in 0..50 {
        if privileged_service::ping() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("CleanWeb 特权服务安装完成但未能启动".into())
}

#[cfg(target_os = "macos")]
fn stage_privileged_service_files(executable: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    // `osascript`-spawned root shells can be denied access to a user's
    // Documents folder by macOS TCC. Stage the already-running executable in
    // the system temporary directory before requesting administrator access.
    let staging = PathBuf::from("/private/tmp").join(format!(
        "cleanweb-service-install-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|value| value.to_string())?
            .as_nanos()
    ));
    fs::create_dir(&staging).map_err(|value| value.to_string())?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .map_err(|value| value.to_string())?;
    let staged = staging.join("app.cleanweb.privileged-service");
    if let Err(value) = fs::copy(executable, &staged) {
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("无法暂存 CleanWeb 特权服务：{value}"));
    }
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))
        .map_err(|value| value.to_string())?;
    Ok(staging)
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
    let mut interfaces: Vec<String> = Command::new("route")
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
    let routed = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
        .map(|value| routed_tunnel_interfaces(&value))
        .unwrap_or_default();
    interfaces.extend(routed);
    interfaces.sort();
    interfaces.dedup();
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
    let system_proxies = Command::new("scutil")
        .arg("--proxy")
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
        .map(|value| active_system_proxies(&value))
        .unwrap_or_default();
    NetworkConflicts {
        has_conflict: !interfaces.is_empty()
            || !vpn_services.is_empty()
            || !system_proxies.is_empty(),
        interfaces,
        vpn_services,
        system_proxies,
    }
}

#[cfg(target_os = "macos")]
fn routed_tunnel_interfaces(table: &str) -> Vec<String> {
    let mut interfaces = table
        .lines()
        .filter_map(|line| {
            line.split_whitespace().find(|field| {
                field.starts_with("utun") || field.starts_with("ppp") || field.starts_with("ipsec")
            })
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    interfaces.sort();
    interfaces.dedup();
    interfaces
}

#[cfg(target_os = "macos")]
fn active_system_proxies(output: &str) -> Vec<String> {
    let fields = output
        .lines()
        .filter_map(|line| line.trim().split_once(" : "))
        .collect::<std::collections::HashMap<_, _>>();
    let mut proxies = Vec::new();
    for (label, prefix) in [("HTTP", "HTTP"), ("HTTPS", "HTTPS"), ("SOCKS", "SOCKS")] {
        if fields.get(&format!("{prefix}Enable").as_str()) != Some(&"1") {
            continue;
        }
        let host = fields
            .get(&format!("{prefix}Proxy").as_str())
            .copied()
            .unwrap_or("unknown");
        let port = fields
            .get(&format!("{prefix}Port").as_str())
            .copied()
            .unwrap_or("?");
        proxies.push(format!("{label} {host}:{port}"));
    }
    if fields.get("ProxyAutoConfigEnable") == Some(&"1") {
        proxies.push(format!(
            "PAC {}",
            fields
                .get("ProxyAutoConfigURLString")
                .copied()
                .unwrap_or("已启用")
        ));
    }
    proxies
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|value| String::from_utf8(value.stdout).ok())
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
            !value.interfaces.is_empty()
                || !value.vpn_services.is_empty()
                || !value.system_proxies.is_empty()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn selects_an_unused_concrete_utun_name() {
        assert_eq!(first_available_utun("lo0 en0 utun200 utun201"), "utun202");
        assert_eq!(first_available_utun("lo0 en0"), "utun200");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn detects_split_default_routes_owned_by_another_tun() {
        let table = "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 10.0.0.1 UGScg en0\n1 198.18.0.1 UGSc utun4\n2/7 198.18.0.1 UGSc utun4\n10.0.0/24 link#11 UCS en0 !\n";
        assert_eq!(routed_tunnel_interfaces(table), vec!["utun4"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn detects_enabled_loopback_system_proxies() {
        let output = "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 7897\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 7897\n  HTTPSProxy : 127.0.0.1\n  SOCKSEnable : 0\n  ProxyAutoConfigEnable : 0\n}";
        assert_eq!(
            active_system_proxies(output),
            vec!["HTTP 127.0.0.1:7897", "HTTPS 127.0.0.1:7897"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn requires_cleanweb_on_the_default_dns_resolver() {
        let healthy = "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n  flags : Request A records\n\nresolver #2\n  nameserver[0] : 10.0.0.1\n";
        assert!(dns_output_uses_loopback(healthy));

        let bypassed = "DNS configuration\n\nresolver #1\n  nameserver[0] : 10.0.0.1\n\nresolver #2\n  nameserver[0] : 127.0.0.1\n";
        assert!(!dns_output_uses_loopback(bypassed));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stages_privileged_helper_outside_tcc_protected_source_directory() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("cleanweb");
        fs::write(&source, b"test-helper").unwrap();

        let staging = stage_privileged_service_files(&source).unwrap();
        let staged = staging.join("app.cleanweb.privileged-service");

        assert!(staging.starts_with("/private/tmp"));
        assert_eq!(fs::read(staged).unwrap(), b"test-helper");
        fs::remove_dir_all(staging).unwrap();
    }
}
