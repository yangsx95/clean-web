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
    Vec::new()
}

pub fn recommended_rule_sources() -> Vec<RecommendedSource> {
    Vec::new()
}
