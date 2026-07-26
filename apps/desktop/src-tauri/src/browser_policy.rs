use std::{
    fs,
    path::Path,
    process::Command,
};

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
    label: &'static str,
    configured: bool,
    current_value: Option<String>,
    expected_value: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct BrowserPolicy {
    id: &'static str,
    name: &'static str,
    app_path: &'static str,
    domain: &'static str,
    managed_path: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct PolicyKey {
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
        domain: "com.google.Chrome",
        managed_path: "/Library/Managed Preferences/com.google.Chrome.plist",
    },
    BrowserPolicy {
        id: "edge",
        name: "Edge",
        app_path: "/Applications/Microsoft Edge.app",
        domain: "com.microsoft.Edge",
        managed_path: "/Library/Managed Preferences/com.microsoft.Edge.plist",
    },
];

const POLICY_KEYS: &[PolicyKey] = &[
    PolicyKey {
        key: "ForceGoogleSafeSearch",
        label: "强制 Google SafeSearch",
        value_type: PolicyValueType::Bool,
        expected_value: "true",
    },
    PolicyKey {
        key: "ForceYouTubeRestrict",
        label: "YouTube 受限模式",
        value_type: PolicyValueType::Int,
        expected_value: "2",
    },
    PolicyKey {
        key: "DnsOverHttpsMode",
        label: "关闭浏览器 DoH",
        value_type: PolicyValueType::String,
        expected_value: "off",
    },
];

#[tauri::command]
pub fn get_browser_policy_status() -> Result<BrowserPolicyStatus, String> {
    browser_policy_status()
}

#[tauri::command]
pub fn apply_browser_policies(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<BrowserPolicyStatus, String> {
    state.require_session(&session_token)?;
    apply_browser_policies_inner()?;
    browser_policy_status()
}

fn browser_policy_status() -> Result<BrowserPolicyStatus, String> {
    Ok(BrowserPolicyStatus {
        browsers: BROWSERS.iter().map(browser_status).collect(),
    })
}

fn browser_status(browser: &BrowserPolicy) -> BrowserPolicyBrowserStatus {
    let installed = Path::new(browser.app_path).exists();
    let details: Vec<BrowserPolicyDetail> = POLICY_KEYS
        .iter()
        .map(|policy| {
            let current_value = read_policy_value(browser.domain, policy.key).ok();
            BrowserPolicyDetail {
                label: policy.label,
                configured: current_value.as_deref() == Some(policy.expected_value),
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

fn apply_browser_policies_inner() -> Result<(), String> {
    let temp_dir = std::env::temp_dir().join("cleanweb-browser-policies");
    fs::create_dir_all(&temp_dir).map_err(|reason| format!("无法创建浏览器策略缓存：{reason}"))?;
    let mut install_commands = vec!["set -e".to_string()];
    install_commands.push("/bin/mkdir -p '/Library/Managed Preferences'".to_string());
    for browser in BROWSERS {
        if !Path::new(browser.app_path).exists() {
            continue;
        }
        let temp_file = temp_dir.join(format!("{}.plist", browser.domain));
        fs::write(&temp_file, browser_policy_plist())
            .map_err(|reason| format!("无法写入浏览器策略文件：{reason}"))?;
        install_commands.push(format!(
            "/usr/bin/install -o root -g wheel -m 644 {} {}",
            shell_quote(&temp_file),
            shell_quote(Path::new(browser.managed_path))
        ));
    }
    if install_commands.len() == 2 {
        return Ok(());
    }
    run_admin_shell(&install_commands.join("; "))?;
    Ok(())
}

fn read_policy_value(domain: &str, key: &str) -> Result<String, String> {
    let browser = BROWSERS
        .iter()
        .find(|browser| browser.domain == domain)
        .ok_or("未知浏览器策略域")?;
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}"), browser.managed_path])
        .output()
        .map_err(|reason| format!("读取浏览器策略失败：{reason}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(normalize_defaults_value(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

fn browser_policy_plist() -> String {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
    );
    for policy in POLICY_KEYS {
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
        return Err(if message.contains("User canceled") || message.contains("-128") {
            "已取消管理员授权，浏览器增强保护未配置".into()
        } else {
            format!("macOS 管理员授权失败：{message}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
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
    use super::{browser_policy_plist, normalize_defaults_value};

    #[test]
    fn normalizes_defaults_boolean_values() {
        assert_eq!(normalize_defaults_value("1"), "true");
        assert_eq!(normalize_defaults_value("0"), "false");
        assert_eq!(normalize_defaults_value("true"), "true");
        assert_eq!(normalize_defaults_value("\"off\""), "off");
    }

    #[test]
    fn writes_managed_browser_policy_plist() {
        let plist = browser_policy_plist();
        assert!(plist.contains("<key>ForceGoogleSafeSearch</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("<key>ForceYouTubeRestrict</key>"));
        assert!(plist.contains("<integer>2</integer>"));
        assert!(plist.contains("<key>DnsOverHttpsMode</key>"));
        assert!(plist.contains("<string>off</string>"));
    }
}
