use std::{path::Path, process::Command};

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
    },
    BrowserPolicy {
        id: "edge",
        name: "Edge",
        app_path: "/Applications/Microsoft Edge.app",
        domain: "com.microsoft.Edge",
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
    for browser in BROWSERS {
        if !Path::new(browser.app_path).exists() {
            continue;
        }
        for policy in POLICY_KEYS {
            write_policy_value(browser.domain, policy)?;
        }
    }
    Ok(())
}

fn read_policy_value(domain: &str, key: &str) -> Result<String, String> {
    let output = Command::new("defaults")
        .args(["read", domain, key])
        .output()
        .map_err(|reason| format!("读取浏览器策略失败：{reason}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(normalize_defaults_value(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

fn write_policy_value(domain: &str, policy: &PolicyKey) -> Result<(), String> {
    let mut command = Command::new("defaults");
    command.args(["write", domain, policy.key]);
    match policy.value_type {
        PolicyValueType::Bool => {
            command.args(["-bool", policy.expected_value]);
        }
        PolicyValueType::Int => {
            command.args(["-int", policy.expected_value]);
        }
        PolicyValueType::String => {
            command.args(["-string", policy.expected_value]);
        }
    }
    let output = command
        .output()
        .map_err(|reason| format!("写入浏览器策略失败：{reason}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn normalize_defaults_value(value: &str) -> String {
    match value.trim() {
        "1" => "true".into(),
        "0" => "false".into(),
        other => other.trim_matches('"').to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_defaults_value;

    #[test]
    fn normalizes_defaults_boolean_values() {
        assert_eq!(normalize_defaults_value("1"), "true");
        assert_eq!(normalize_defaults_value("0"), "false");
        assert_eq!(normalize_defaults_value("\"off\""), "off");
    }
}
