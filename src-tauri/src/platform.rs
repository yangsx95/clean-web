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
const SYSTEM_RUNTIME_DIR: &str = "/Library/Application Support/CleanWeb";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConflicts {
    pub has_conflict: bool,
    pub interfaces: Vec<String>,
    pub vpn_services: Vec<String>,
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
        let expected = format!("{SYSTEM_RUNTIME_DIR}/mihomo");
        return run_command("/bin/ps", &["-p", &pid.to_string(), "-o", "command="])
            .is_some_and(|command| command.contains(&expected));
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
        return run_admin_shell(&format!("/bin/kill -{signal} {pid}")).is_ok();
    }
    false
}

/// Installs a root-owned copy of the validated core and its generated config,
/// then starts it with the privileges required to create a macOS TUN device.
#[cfg(target_os = "macos")]
pub fn start_mihomo_privileged(binary: &Path, config: &Path) -> Result<(u32, PathBuf), String> {
    let system_dir = PathBuf::from(SYSTEM_RUNTIME_DIR);
    let installed_binary = system_dir.join("mihomo");
    let installed_config = system_dir.join("config.yaml");
    let log = system_dir.join("mihomo.log");
    let command = format!(
        "/bin/mkdir -p {dir} && /usr/bin/install -o root -g wheel -m 700 {source_binary} {binary} && /usr/bin/install -o root -g wheel -m 600 {source_config} {config} && /usr/bin/touch {log} && /bin/chmod 644 {log} && : > {log} && {{ {binary} -d {dir} -f {config} >> {log} 2>&1 & echo $!; }}",
        dir = shell_quote(&system_dir),
        source_binary = shell_quote(binary),
        binary = shell_quote(&installed_binary),
        source_config = shell_quote(config),
        config = shell_quote(&installed_config),
        log = shell_quote(&log),
    );
    let output = run_admin_shell(&command)?;
    let pid = output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<u32>().ok())
        .ok_or_else(|| format!("管理员启动未返回 Mihomo PID：{output}"))?;
    Ok((pid, log))
}

#[cfg(target_os = "macos")]
fn run_admin_shell(command: &str) -> Result<String, String> {
    let output = Command::new("/usr/bin/osascript")
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
            !value.interfaces.is_empty() || !value.vpn_services.is_empty()
        );
    }
}
