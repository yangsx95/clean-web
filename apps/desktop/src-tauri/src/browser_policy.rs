use std::{collections::HashMap, fs, path::Path, process::Command};

use rusqlite::{params, Connection};
use serde::Serialize;
use tauri::State;

use crate::storage::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPolicyStatus {
    browsers: Vec<BrowserPolicyBrowserStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPolicyBrowserStatus {
    id: &'static str,
    name: &'static str,
    installed: bool,
    configured: bool,
    needs_restart: bool,
    details: Vec<BrowserPolicyDetail>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPolicyDetail {
    key: &'static str,
    label: &'static str,
    enabled: bool,
    configured: bool,
    current_value: Option<String>,
    expected_value: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct BrowserPolicy {
    id: &'static str,
    name: &'static str,
    app_path: &'static str,
    managed_domains: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
struct PolicyKey {
    setting_key: &'static str,
    key: &'static str,
    label: &'static str,
    value_type: PolicyValueType,
    expected_value: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum PolicyValueType {
    Bool,
    Int,
    String,
}

const BROWSERS: &[BrowserPolicy] = &[
    BrowserPolicy {
        id: "chrome",
        name: "Chrome",
        app_path: "/Applications/Google Chrome.app",
        managed_domains: &["com.google.Chrome"],
    },
    BrowserPolicy {
        id: "edge",
        name: "Edge",
        app_path: "/Applications/Microsoft Edge.app",
        managed_domains: &["com.microsoft.Edge"],
    },
    BrowserPolicy {
        id: "brave",
        name: "Brave",
        app_path: "/Applications/Brave Browser.app",
        managed_domains: &["com.brave.Browser"],
    },
    BrowserPolicy {
        id: "vivaldi",
        name: "Vivaldi",
        app_path: "/Applications/Vivaldi.app",
        managed_domains: &["com.vivaldi.Vivaldi"],
    },
    BrowserPolicy {
        id: "chromium",
        name: "Chromium",
        app_path: "/Applications/Chromium.app",
        managed_domains: &["org.chromium.Chromium"],
    },
];

const POLICY_KEYS: &[PolicyKey] = &[
    PolicyKey {
        setting_key: "browser_policy.force_google_safe_search",
        key: "ForceGoogleSafeSearch",
        label: "强制 Google SafeSearch",
        value_type: PolicyValueType::Bool,
        expected_value: "true",
    },
    PolicyKey {
        setting_key: "browser_policy.force_youtube_restrict",
        key: "ForceYouTubeRestrict",
        label: "YouTube 受限模式",
        value_type: PolicyValueType::Int,
        expected_value: "2",
    },
    PolicyKey {
        setting_key: "browser_policy.disable_doh",
        key: "DnsOverHttpsMode",
        label: "关闭浏览器 DoH",
        value_type: PolicyValueType::String,
        expected_value: "off",
    },
    PolicyKey {
        setting_key: "browser_policy.use_system_dns_client",
        key: "BuiltInDnsClientEnabled",
        label: "使用系统 DNS 客户端",
        value_type: PolicyValueType::Bool,
        expected_value: "false",
    },
];

#[tauri::command]
pub fn get_browser_policy_status(
    state: State<'_, AppState>,
) -> Result<BrowserPolicyStatus, String> {
    browser_policy_status(&state)
}

#[tauri::command]
pub fn apply_browser_policies(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<BrowserPolicyStatus, String> {
    state.require_session(&session_token)?;
    apply_browser_policies_inner(&state)?;
    browser_policy_status(&state)
}

fn browser_policy_status(state: &AppState) -> Result<BrowserPolicyStatus, String> {
    let enabled = enabled_policy_settings(state)?;
    Ok(BrowserPolicyStatus {
        browsers: BROWSERS
            .iter()
            .map(|browser| browser_status(browser, &enabled))
            .collect(),
    })
}

fn browser_status(
    browser: &BrowserPolicy,
    enabled: &HashMap<&'static str, bool>,
) -> BrowserPolicyBrowserStatus {
    let installed = Path::new(browser.app_path).exists();
    let details: Vec<BrowserPolicyDetail> = POLICY_KEYS
        .iter()
        .map(|policy| {
            let enabled = enabled.get(policy.setting_key).copied().unwrap_or(true);
            let current_value = read_policy_value(browser, policy.key).ok();
            BrowserPolicyDetail {
                key: policy.setting_key,
                label: policy.label,
                enabled,
                configured: !enabled || current_value.as_deref() == Some(policy.expected_value),
                current_value,
                expected_value: policy.expected_value,
            }
        })
        .collect();
    let configured = details.iter().all(|detail| detail.configured);
    BrowserPolicyBrowserStatus {
        id: browser.id,
        name: browser.name,
        installed,
        configured,
        needs_restart: installed && configured,
        details,
    }
}

fn apply_browser_policies_inner(state: &AppState) -> Result<(), String> {
    let enabled = enabled_policy_settings(state)?;
    let active_policies = POLICY_KEYS
        .iter()
        .copied()
        .filter(|policy| enabled.get(policy.setting_key).copied().unwrap_or(true))
        .collect::<Vec<_>>();
    let temp_dir = std::env::temp_dir().join("cleanweb-browser-policies");
    fs::create_dir_all(&temp_dir).map_err(|reason| format!("无法创建浏览器策略缓存：{reason}"))?;
    let mut install_commands = vec!["set -e".to_string()];
    install_commands.push("/bin/mkdir -p '/Library/Managed Preferences'".to_string());
    let user = console_user();
    if let Some(user) = user.as_deref() {
        install_commands.push(format!(
            "/bin/mkdir -p {}",
            shell_quote(&Path::new("/Library/Managed Preferences").join(&user))
        ));
    }
    let mut installed_browser_count = 0;
    for browser in BROWSERS {
        if !Path::new(browser.app_path).exists() {
            continue;
        }
        installed_browser_count += 1;
        for domain in browser.managed_domains {
            let temp_file = temp_dir.join(format!("{domain}.plist"));
            fs::write(&temp_file, browser_policy_plist(&active_policies))
                .map_err(|reason| format!("无法写入浏览器策略文件：{reason}"))?;
            install_commands.push(format!(
                "/usr/bin/install -o root -g wheel -m 644 {} {}",
                shell_quote(&temp_file),
                shell_quote(&managed_policy_path(domain))
            ));
            if let Some(user) = user.as_deref() {
                install_commands.push(format!(
                    "/usr/bin/install -o root -g wheel -m 644 {} {}",
                    shell_quote(&temp_file),
                    shell_quote(&user_managed_policy_path(user, domain))
                ));
            }
        }
    }
    if installed_browser_count == 0 {
        return Ok(());
    }
    run_admin_shell(&install_commands.join("; "))?;
    Ok(())
}

fn enabled_policy_settings(state: &AppState) -> Result<HashMap<&'static str, bool>, String> {
    let db = state.db.lock().map_err(|_| "数据库不可用")?;
    Ok(enabled_policy_settings_from_db(&db))
}

fn enabled_policy_settings_from_db(db: &Connection) -> HashMap<&'static str, bool> {
    let mut result = HashMap::new();
    for policy in POLICY_KEYS {
        let enabled = db
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![policy.setting_key],
                |row| row.get::<_, String>(0),
            )
            .map(|value| value == "true")
            .unwrap_or(true);
        result.insert(policy.setting_key, enabled);
    }
    result
}

fn read_policy_value(browser: &BrowserPolicy, key: &str) -> Result<String, String> {
    let mut candidates = Vec::new();
    let user = console_user();
    for domain in browser.managed_domains {
        if let Some(user) = user.as_deref() {
            candidates.push(user_managed_policy_path(user, domain));
        }
        candidates.push(managed_policy_path(domain));
    }
    for path in candidates {
        let output = Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :{key}"), &path.to_string_lossy()])
            .output()
            .map_err(|reason| format!("读取浏览器策略失败：{reason}"))?;
        if output.status.success() {
            return Ok(normalize_defaults_value(
                String::from_utf8_lossy(&output.stdout).trim(),
            ));
        }
    }
    Err("浏览器策略尚未配置".into())
}

fn browser_policy_plist(policies: &[PolicyKey]) -> String {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
    );
    for policy in policies {
        body.push_str(&format!("  <key>{}</key>\n", policy.key));
        match policy.value_type {
            PolicyValueType::Bool => {
                body.push_str(if policy.expected_value == "true" {
                    "  <true/>\n"
                } else {
                    "  <false/>\n"
                });
            }
            PolicyValueType::Int => {
                body.push_str(&format!("  <integer>{}</integer>\n", policy.expected_value));
            }
            PolicyValueType::String => {
                body.push_str(&format!(
                    "  <string>{}</string>\n",
                    xml_escape(policy.expected_value)
                ));
            }
        }
    }
    body.push_str("</dict>\n</plist>\n");
    body
}

fn normalize_defaults_value(value: &str) -> String {
    match value.trim() {
        "1" => "true".into(),
        "0" => "false".into(),
        "true" => "true".into(),
        "false" => "false".into(),
        other => other.trim_matches('"').to_string(),
    }
}

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
        .map_err(|reason| format!("无法请求 macOS 管理员权限：{reason}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(
            if message.contains("User canceled") || message.contains("-128") {
                "已取消管理员授权，浏览器增强保护未配置".into()
            } else {
                format!("macOS 管理员授权失败：{message}")
            },
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn console_user() -> Option<String> {
    let output = Command::new("/usr/bin/stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if user.is_empty() || user == "root" {
        None
    } else {
        Some(user)
    }
}

fn user_managed_policy_path(user: &str, domain: &str) -> std::path::PathBuf {
    Path::new("/Library/Managed Preferences")
        .join(user)
        .join(format!("{domain}.plist"))
}

fn managed_policy_path(domain: &str) -> std::path::PathBuf {
    Path::new("/Library/Managed Preferences").join(format!("{domain}.plist"))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::{browser_policy_plist, normalize_defaults_value, POLICY_KEYS};

    #[test]
    fn normalizes_defaults_boolean_values() {
        assert_eq!(normalize_defaults_value("1"), "true");
        assert_eq!(normalize_defaults_value("0"), "false");
        assert_eq!(normalize_defaults_value("true"), "true");
        assert_eq!(normalize_defaults_value("\"off\""), "off");
    }

    #[test]
    fn writes_managed_browser_policy_plist() {
        let plist = browser_policy_plist(POLICY_KEYS);
        assert!(plist.contains("<key>ForceGoogleSafeSearch</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("<key>ForceYouTubeRestrict</key>"));
        assert!(plist.contains("<integer>2</integer>"));
        assert!(plist.contains("<key>DnsOverHttpsMode</key>"));
        assert!(plist.contains("<string>off</string>"));
        assert!(plist.contains("<key>BuiltInDnsClientEnabled</key>"));
        assert!(plist.contains("<false/>"));
    }

    #[test]
    fn omits_disabled_browser_policy_keys_from_plist() {
        let policies = POLICY_KEYS
            .iter()
            .copied()
            .filter(|policy| policy.key != "DnsOverHttpsMode")
            .collect::<Vec<_>>();
        let plist = browser_policy_plist(&policies);

        assert!(plist.contains("<key>ForceGoogleSafeSearch</key>"));
        assert!(!plist.contains("<key>DnsOverHttpsMode</key>"));
    }
}
