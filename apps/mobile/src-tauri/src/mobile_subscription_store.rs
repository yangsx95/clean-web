use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
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

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn write_subscription_rules(
    store_dir: &Path,
    id: &str,
    rules: impl IntoIterator<Item = StoredSubscriptionRule>,
) -> Result<(), String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = subscription_rules_path(store_dir, id);
    let tmp = path.with_extension("rules.jsonl.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    for rule in rules {
        serde_json::to_writer(&mut file, &rule).map_err(error)?;
        file.write_all(b"\n").map_err(error)?;
    }
    file.sync_all().map_err(error)?;
    fs::rename(tmp, path).map_err(error)?;
    Ok(())
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn write_safe_search_mappings(
    store_dir: &Path,
    id: &str,
    mappings: impl IntoIterator<Item = StoredSafeSearchMapping>,
) -> Result<(), String> {
    fs::create_dir_all(store_dir).map_err(error)?;
    let path = safe_search_mappings_path(store_dir, id);
    let tmp = path.with_extension("safe-search.jsonl.tmp");
    let mut file = File::create(&tmp).map_err(error)?;
    for mapping in mappings {
        serde_json::to_writer(&mut file, &mapping).map_err(error)?;
        file.write_all(b"\n").map_err(error)?;
    }
    file.sync_all().map_err(error)?;
    fs::rename(tmp, path).map_err(error)?;
    Ok(())
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

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}
