use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DefaultRuleSource {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub fallback: Option<String>,
    pub format: String,
    pub category: String,
    pub update_interval_hours: Option<i64>,
    #[serde(default)]
    pub ui_group: Option<String>,
    #[serde(default)]
    pub ui_order: Option<i64>,
    #[serde(default)]
    pub toggleable: bool,
    #[serde(default)]
    pub enabled_by_default: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedSource {
    pub name: String,
    pub url: String,
    pub format: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleSourceDefaults {
    #[serde(default)]
    pub default_rule_sources: Vec<DefaultRuleSource>,
    #[serde(default)]
    pub rule_packs: Vec<DefaultRuleSource>,
    #[serde(default)]
    pub recommended_rule_sources: Vec<RecommendedSource>,
}

pub fn parse_rule_source_defaults(text: &str) -> Result<RuleSourceDefaults, String> {
    let defaults: RuleSourceDefaults =
        serde_yaml::from_str(text).map_err(|value| value.to_string())?;
    for source in defaults
        .default_rule_sources
        .iter()
        .chain(defaults.rule_packs.iter())
    {
        validate_rule_source(&source.url, &source.id)?;
        if let Some(fallback) = source.fallback.as_deref() {
            validate_rule_source(fallback, &format!("{} fallback", source.id))?;
        }
    }
    for source in &defaults.recommended_rule_sources {
        validate_rule_source(&source.url, &source.name)?;
    }
    Ok(defaults)
}

impl RuleSourceDefaults {
    pub fn all_rule_sources(&self) -> Vec<DefaultRuleSource> {
        self.default_rule_sources
            .iter()
            .chain(self.rule_packs.iter())
            .cloned()
            .collect()
    }
}

pub fn validate_rule_source(value: &str, label: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("rule source {label} is empty"));
    }
    if let Some((scheme, _)) = value.split_once("://") {
        if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https" | "file") {
            return Err(format!(
                "rule source {label} must be a local path, file URL, or HTTP(S) URL"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_sources_and_rule_packs() {
        let parsed = parse_rule_source_defaults(
            r#"
default_rule_sources:
  - id: default:test:source
    name: Test Source
    url: https://example.test/source.txt
    format: hosts
    category: ads
    update_interval_hours: 24
    ui_group: 隐私与广告
    ui_order: 10
    toggleable: true
    enabled_by_default: false
    description: Optional ads source
rule_packs:
  - id: default:test:pack
    name: Test Pack
    url: https://example.test/pack.txt
    format: clash
    category: strict
recommended_rule_sources:
  - name: Recommended
    url: https://example.test/recommended.txt
    format: hosts
    category: ads
    description: Optional source
"#,
        )
        .unwrap();

        let sources = parsed.all_rule_sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].id, "default:test:source");
        assert_eq!(sources[0].ui_group.as_deref(), Some("隐私与广告"));
        assert_eq!(sources[0].ui_order, Some(10));
        assert!(sources[0].toggleable);
        assert_eq!(sources[0].enabled_by_default, Some(false));
        assert_eq!(sources[0].description.as_deref(), Some("Optional ads source"));
        assert_eq!(sources[1].id, "default:test:pack");
        assert_eq!(parsed.recommended_rule_sources.len(), 1);
    }

    #[test]
    fn accepts_local_and_remote_rule_sources() {
        for source in [
            "/opt/cleanweb/rules.clash",
            "./rules/rules.clash",
            "file:///opt/cleanweb/rules.clash",
            "http://127.0.0.1:8080/rules.clash",
            "https://example.test/rules.clash",
        ] {
            validate_rule_source(source, "test").unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_rule_source_schemes() {
        let error = parse_rule_source_defaults(
            r#"
default_rule_sources:
  - id: default:test:source
    name: Test Source
    url: builtin://test/source
    format: clash
    category: custom
"#,
        )
        .unwrap_err();

        assert!(error.contains("must be a local path, file URL, or HTTP(S) URL"));
    }
}
