//! Cross-platform abstractions for OS-specific operations.
//!
//! All process signaling, OS version detection, and network conflict detection
//! lives here so the rest of CleanWeb compiles on both macOS and Windows. The
//! macOS branches preserve the original behavior; the Windows branches are
//! intentionally minimal and documented where they diverge (see the
//! "fail-open" policy in docs/architecture.md).

use serde::Serialize;
use std::process::Command;

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
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        // TODO(Windows): reliable PID liveness needs OpenProcess; deferred.
        // The in-process child handle covers the normal lifecycle; returning
        // false disables only cross-session crash recovery on Windows.
        let _ = pid;
        false
    }
}

/// Politely requests a process to terminate (SIGTERM on Unix).
pub fn terminate_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, libc::SIGTERM) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Forcefully kills a process (SIGKILL on Unix).
pub fn kill_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
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
