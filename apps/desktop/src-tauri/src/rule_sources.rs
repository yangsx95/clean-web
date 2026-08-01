use serde::Serialize;

#[derive(Debug, Clone)]
pub struct DefaultRuleSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub category: String,
    pub update_interval_hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedSource {
    pub name: String,
    pub url: String,
    pub format: String,
    pub category: String,
    pub description: String,
}

pub fn default_rule_sources() -> Vec<DefaultRuleSource> {
    vec![DefaultRuleSource {
        id: "default:cleanweb:safe-search".into(),
        name: "内置规则 · CleanWeb SafeSearch".into(),
        url: "https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-safe-search.yaml".into(),
        format: "safe-search".into(),
        category: "custom".into(),
        update_interval_hours: Some(24),
    }]
}

pub fn recommended_rule_sources() -> Vec<RecommendedSource> {
    Vec::new()
}
