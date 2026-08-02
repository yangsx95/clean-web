use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DefaultRuleSource {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub legacy_urls: Vec<String>,
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
    serde_yaml::from_str(text).map_err(|value| value.to_string())
}

impl RuleSourceDefaults {
    pub fn bundled_rule_sources(&self) -> Vec<DefaultRuleSource> {
        self.default_rule_sources
            .iter()
            .chain(self.rule_packs.iter())
            .cloned()
            .collect()
    }
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
    legacy_urls:
      - builtin://test/pack
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

        let bundled = parsed.bundled_rule_sources();
        assert_eq!(bundled.len(), 2);
        assert_eq!(bundled[0].id, "default:test:source");
        assert_eq!(bundled[0].ui_group.as_deref(), Some("隐私与广告"));
        assert_eq!(bundled[0].ui_order, Some(10));
        assert!(bundled[0].toggleable);
        assert_eq!(bundled[0].enabled_by_default, Some(false));
        assert_eq!(bundled[0].description.as_deref(), Some("Optional ads source"));
        assert_eq!(bundled[1].id, "default:test:pack");
        assert_eq!(parsed.recommended_rule_sources.len(), 1);
    }
}
