pub use cleanweb_rules::*;

pub(crate) struct BundledRuleSource {
    pub id: &'static str,
    pub content: &'static str,
}

/// Offline bootstrap copies for rule subscriptions that are maintained remotely.
/// Runtime policy always reads the imported database rows, so a successful
/// subscription refresh fully replaces these packaged copies.
pub(crate) fn bundled_rule_sources() -> [BundledRuleSource; 3] {
    [
        BundledRuleSource {
            id: "local:cleanweb:entertainment-short-video",
            content: include_str!(
                "../../../../resources/rules/cleanweb-entertainment-short-video.clash"
            ),
        },
        BundledRuleSource {
            id: "local:cleanweb:entertainment-social",
            content: include_str!(
                "../../../../resources/rules/cleanweb-entertainment-social.clash"
            ),
        },
        BundledRuleSource {
            id: "local:cleanweb:entertainment-games",
            content: include_str!("../../../../resources/rules/cleanweb-entertainment-games.clash"),
        },
    ]
}
