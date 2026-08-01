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
        name: "CleanWeb · SafeSearch DNS Mappings".into(),
        url: "https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-safe-search.yaml".into(),
        format: "safe-search".into(),
        category: "custom".into(),
        update_interval_hours: Some(24),
    }]
}

pub fn builtin_source_display_names() -> &'static [(&'static str, &'static str)] {
    &[
        ("default:stevenblack:porn", "StevenBlack · Porn-only Hosts"),
        (
            "default:blocklistproject:porn",
            "The Block List Project · Porn (NL)",
        ),
        (
            "default:stevenblack:gambling",
            "StevenBlack · Gambling-only Hosts",
        ),
        (
            "default:blocklistproject:drugs",
            "The Block List Project · Drugs (NL)",
        ),
        (
            "default:blocklistproject:fraud",
            "The Block List Project · Fraud (NL)",
        ),
        (
            "default:blocklistproject:phishing",
            "The Block List Project · Phishing (NL)",
        ),
        ("default:urlhaus:malware", "URLhaus · Malware Hostfile"),
        (
            "default:cleanweb:adult-supplement",
            "CleanWeb · Adult Supplement",
        ),
        (
            "default:cleanweb:security-supplement",
            "CleanWeb · Security Supplement",
        ),
        (
            "default:cleanweb:safe-search",
            "CleanWeb · SafeSearch DNS Mappings",
        ),
        (
            "local:cleanweb:entertainment-cdn",
            "CleanWeb · Entertainment CDN Supplement",
        ),
        (
            "default:loyalsoldier:cncidr",
            "Loyalsoldier · China CIDR Routes",
        ),
        (
            "default:cleanweb:strict-supplement",
            "CleanWeb · Strict Mode Supplement",
        ),
    ]
}

pub fn recommended_rule_sources() -> Vec<RecommendedSource> {
    Vec::new()
}
