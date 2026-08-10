use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use cleanweb_rules::{Action, MatcherKind, RuleInput};
use cleanweb_subscriptions::SafeSearchMapping;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSubscriptionRule {
    pub id: String,
    pub action: Action,
    pub priority: u16,
    pub kind: MatcherKind,
    pub pattern: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSafeSearchMapping {
    pub domain: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredProxyNode {
    pub name: String,
    pub node_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredProxyGroup {
    pub name: String,
    pub group_type: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredProxyInfo {
    pub proxies: Vec<StoredProxyNode>,
    pub groups: Vec<StoredProxyGroup>,
}

impl From<RuleInput> for StoredSubscriptionRule {
    fn from(value: RuleInput) -> Self {
        Self {
            id: value.id,
            action: value.action,
            priority: value.priority,
            kind: value.kind,
            pattern: value.pattern,
            category: value.category,
        }
    }
}

impl From<StoredSubscriptionRule> for RuleInput {
    fn from(value: StoredSubscriptionRule) -> Self {
        Self {
            id: value.id,
            action: value.action,
            priority: value.priority,
            kind: value.kind,
            pattern: value.pattern,
            category: value.category,
        }
    }
}

impl From<SafeSearchMapping> for StoredSafeSearchMapping {
    fn from(value: SafeSearchMapping) -> Self {
        Self {
            domain: value.domain,
            target: value.target,
        }
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn subscription_store_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("rule-subscriptions")
}

pub fn subscription_rules_path(store_dir: &Path, id: &str) -> PathBuf {
    store_dir.join(format!("{}.rules.jsonl", safe_file_stem(id)))
}

pub fn safe_search_mappings_path(store_dir: &Path, id: &str) -> PathBuf {
    store_dir.join(format!("{}.safe-search.jsonl", safe_file_stem(id)))
}

pub fn proxy_info_path(store_dir: &Path, id: &str) -> PathBuf {
    store_dir.join(format!("{}.proxy.json", safe_file_stem(id)))
}

pub fn proxy_payload_path(store_dir: &Path, id: &str) -> PathBuf {
    store_dir.join(format!("{}.proxy.yaml", safe_file_stem(id)))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn replace_subscription_rules(
    store_dir: &Path,
    id: &str,
    rules: impl IntoIterator<Item = StoredSubscriptionRule>,
) -> Result<bool, String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = subscription_rules_path(store_dir, id);
    let tmp = path.with_extension("rules.jsonl.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    for rule in rules {
        serde_json::to_writer(&mut file, &rule).map_err(error)?;
        file.write_all(b"\n").map_err(error)?;
    }
    file.sync_all().map_err(error)?;
    replace_if_changed(&tmp, &path)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn replace_safe_search_mappings(
    store_dir: &Path,
    id: &str,
    mappings: impl IntoIterator<Item = StoredSafeSearchMapping>,
) -> Result<bool, String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = safe_search_mappings_path(store_dir, id);
    let tmp = path.with_extension("safe-search.jsonl.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    for mapping in mappings {
        serde_json::to_writer(&mut file, &mapping).map_err(error)?;
        file.write_all(b"\n").map_err(error)?;
    }
    file.sync_all().map_err(error)?;
    replace_if_changed(&tmp, &path)
}

pub fn read_subscription_rules(store_dir: &Path, id: &str) -> Result<Vec<RuleInput>, String> {
    let path = subscription_rules_path(store_dir, id);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(error)?;
    let mut rules = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(error)?;
        if line.trim().is_empty() {
            continue;
        }
        let rule: StoredSubscriptionRule = serde_json::from_str(&line).map_err(error)?;
        rules.push(rule.into());
    }
    Ok(rules)
}

pub fn read_safe_search_mappings(
    store_dir: &Path,
    id: &str,
) -> Result<Vec<StoredSafeSearchMapping>, String> {
    let path = safe_search_mappings_path(store_dir, id);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(error)?;
    let mut mappings = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(error)?;
        if line.trim().is_empty() {
            continue;
        }
        mappings.push(serde_json::from_str(&line).map_err(error)?);
    }
    Ok(mappings)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn replace_proxy_info(
    store_dir: &Path,
    id: &str,
    info: &StoredProxyInfo,
) -> Result<bool, String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = proxy_info_path(store_dir, id);
    let tmp = path.with_extension("proxy.json.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    serde_json::to_writer(&mut file, info).map_err(error)?;
    file.write_all(b"\n").map_err(error)?;
    file.sync_all().map_err(error)?;
    replace_if_changed(&tmp, &path)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn read_proxy_info(store_dir: &Path, id: &str) -> Result<StoredProxyInfo, String> {
    let path = proxy_info_path(store_dir, id);
    if !path.exists() {
        return Ok(StoredProxyInfo {
            proxies: Vec::new(),
            groups: Vec::new(),
        });
    }
    let file = File::open(path).map_err(error)?;
    serde_json::from_reader(file).map_err(error)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn replace_proxy_payload(store_dir: &Path, id: &str, payload: &str) -> Result<bool, String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = proxy_payload_path(store_dir, id);
    let tmp = path.with_extension("proxy.yaml.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    file.write_all(payload.as_bytes()).map_err(error)?;
    file.sync_all().map_err(error)?;
    replace_if_changed(&tmp, &path)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn read_proxy_payload(store_dir: &Path, id: &str) -> Result<Option<String>, String> {
    let path = proxy_payload_path(store_dir, id);
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(path).map(Some).map_err(error)
}

fn safe_file_stem(id: &str) -> String {
    id.chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || matches!(value, '-' | '_') {
                value
            } else {
                '_'
            }
        })
        .collect()
}

fn replace_if_changed(candidate: &Path, current: &Path) -> Result<bool, String> {
    if current.exists() && files_equal(candidate, current)? {
        fs::remove_file(candidate).map_err(error)?;
        return Ok(false);
    }
    fs::rename(candidate, current).map_err(error)?;
    Ok(true)
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
    if fs::metadata(left).map_err(error)?.len() != fs::metadata(right).map_err(error)?.len() {
        return Ok(false);
    }
    let mut left = BufReader::new(File::open(left).map_err(error)?);
    let mut right = BufReader::new(File::open(right).map_err(error)?);
    let mut left_buffer = [0_u8; 32 * 1024];
    let mut right_buffer = [0_u8; 32 * 1024];
    loop {
        let left_length = left.read(&mut left_buffer).map_err(error)?;
        let right_length = right.read(&mut right_buffer).map_err(error)?;
        if left_length != right_length || left_buffer[..left_length] != right_buffer[..right_length]
        {
            return Ok(false);
        }
        if left_length == 0 {
            return Ok(true);
        }
    }
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str) -> StoredSubscriptionRule {
        StoredSubscriptionRule {
            id: format!("test:{pattern}"),
            action: Action::Block,
            priority: 50,
            kind: MatcherKind::Exact,
            pattern: pattern.into(),
            category: "test".into(),
        }
    }

    #[test]
    fn atomic_replacement_reports_real_content_changes() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            replace_subscription_rules(directory.path(), "source", [rule("one.example")]).unwrap()
        );
        assert!(
            !replace_subscription_rules(directory.path(), "source", [rule("one.example")]).unwrap()
        );
        assert!(
            replace_subscription_rules(directory.path(), "source", [rule("two.example")]).unwrap()
        );
        let stored = read_subscription_rules(directory.path(), "source").unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].pattern, "two.example");
    }

    #[test]
    fn stores_proxy_info_for_mobile_node_preview() {
        let directory = tempfile::tempdir().unwrap();
        let info = StoredProxyInfo {
            proxies: vec![StoredProxyNode {
                name: "node-a".into(),
                node_type: "ss".into(),
            }],
            groups: vec![StoredProxyGroup {
                name: "auto".into(),
                group_type: "url-test".into(),
                members: vec!["node-a".into()],
            }],
        };
        assert!(replace_proxy_info(directory.path(), "proxy/source", &info).unwrap());
        assert!(!replace_proxy_info(directory.path(), "proxy/source", &info).unwrap());
        assert_eq!(
            read_proxy_info(directory.path(), "proxy/source").unwrap(),
            info
        );
    }

    #[test]
    fn stores_proxy_payload_for_mobile_mihomo_config() {
        let directory = tempfile::tempdir().unwrap();
        let payload = "proxies:\n  - name: node-a\n    type: direct\n";
        assert!(replace_proxy_payload(directory.path(), "proxy/source", payload).unwrap());
        assert!(!replace_proxy_payload(directory.path(), "proxy/source", payload).unwrap());
        assert_eq!(
            read_proxy_payload(directory.path(), "proxy/source").unwrap(),
            Some(payload.into())
        );
    }
}
