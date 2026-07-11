use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::rules::{Action, MatcherKind, RuleInput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionFormat {
    Clash,
    Hosts,
    DomainList,
    IpList,
    Adblock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSource {
    pub subscription_id: String,
    pub source_url: String,
    pub source_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedRule {
    pub rule: RuleInput,
    pub source: RuleSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredLine {
    pub line: usize,
    pub content: String,
    pub reason: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ImportReport {
    pub rules: Vec<ImportedRule>,
    pub ignored: Vec<IgnoredLine>,
}

pub fn import_text(
    format: SubscriptionFormat,
    text: &str,
    subscription_id: &str,
    source_url: &str,
    category: &str,
) -> ImportReport {
    let mut report = ImportReport::default();

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        let result = match format {
            SubscriptionFormat::Clash => parse_clash_line(line),
            SubscriptionFormat::Hosts => parse_hosts_line(line),
            SubscriptionFormat::DomainList => parse_domain_line(line),
            SubscriptionFormat::IpList => parse_ip_line(line),
            SubscriptionFormat::Adblock => parse_adblock_line(line),
        };

        match result {
            Ok(Some((kind, pattern, action))) => report.rules.push(ImportedRule {
                rule: RuleInput {
                    id: format!("{subscription_id}:{line_number}"),
                    action,
                    priority: 70,
                    kind,
                    pattern,
                    category: category.to_owned(),
                },
                source: RuleSource {
                    subscription_id: subscription_id.to_owned(),
                    source_url: source_url.to_owned(),
                    source_line: line_number,
                },
            }),
            Ok(None) => {}
            Err(reason) => report.ignored.push(IgnoredLine {
                line: line_number,
                content: line.to_owned(),
                reason,
            }),
        }
    }

    report
}

fn parse_clash_line(line: &str) -> Result<Option<(MatcherKind, String, Action)>, String> {
    let line = line.trim_start_matches('-').trim();
    let fields: Vec<_> = line.split(',').map(str::trim).collect();
    if fields.len() < 2 {
        return Err("not a supported Clash rule".into());
    }

    let parsed = match fields[0].to_ascii_uppercase().as_str() {
        "DOMAIN" => (MatcherKind::Exact, fields[1].to_owned()),
        "DOMAIN-SUFFIX" => (MatcherKind::Suffix, fields[1].to_owned()),
        "DOMAIN-KEYWORD" => (MatcherKind::Contains, fields[1].to_owned()),
        "IP-CIDR" | "IP-CIDR6" => (MatcherKind::Cidr, fields[1].to_owned()),
        "PROCESS-NAME" | "PROCESS-PATH" | "DST-PORT" | "SRC-PORT" | "MATCH" => {
            return Err("rule type is outside domain/IP filtering".into())
        }
        other => return Err(format!("unsupported Clash rule type: {other}")),
    };
    Ok(Some((parsed.0, parsed.1, action_from_policy(fields.get(2).copied()))))
}

fn parse_hosts_line(line: &str) -> Result<Option<(MatcherKind, String, Action)>, String> {
    let content = line.split('#').next().unwrap_or_default().trim();
    let fields: Vec<_> = content.split_whitespace().collect();
    if fields.len() < 2 {
        return Err("hosts entry must contain an address and domain".into());
    }
    fields[0].parse::<IpAddr>().map_err(|_| "invalid hosts address".to_string())?;
    Ok(Some((MatcherKind::Exact, fields[1].to_owned(), Action::Block)))
}

fn parse_domain_line(line: &str) -> Result<Option<(MatcherKind, String, Action)>, String> {
    let value = line.trim_start_matches("||").trim_end_matches('^').trim();
    if value.contains('/') || value.contains(' ') || value.is_empty() {
        return Err("not a plain domain".into());
    }
    Ok(Some((MatcherKind::Suffix, value.to_owned(), Action::Block)))
}

fn parse_ip_line(line: &str) -> Result<Option<(MatcherKind, String, Action)>, String> {
    if line.parse::<IpAddr>().is_ok() {
        return Ok(Some((MatcherKind::Ip, line.to_owned(), Action::Block)));
    }
    if line.parse::<ipnet::IpNet>().is_ok() {
        return Ok(Some((MatcherKind::Cidr, line.to_owned(), Action::Block)));
    }
    Err("not an IP address or CIDR".into())
}

fn parse_adblock_line(line: &str) -> Result<Option<(MatcherKind, String, Action)>, String> {
    if line.contains("##") || line.contains("#@#") || line.contains("$script") {
        return Err("cosmetic and script rules are unsupported".into());
    }
    if let Some(value) = line.strip_prefix("@@||") {
        return adblock_domain(value, Action::Allow);
    }
    if let Some(value) = line.strip_prefix("||") {
        return adblock_domain(value, Action::Block);
    }
    Err("only Adblock domain rules are supported".into())
}

fn adblock_domain(value: &str, action: Action) -> Result<Option<(MatcherKind, String, Action)>, String> {
    let domain = value.split(['^', '$', '/']).next().unwrap_or_default().trim();
    if domain.is_empty() || domain.contains('*') {
        return Err("complex Adblock patterns are unsupported".into());
    }
    Ok(Some((MatcherKind::Suffix, domain.to_owned(), action)))
}

fn action_from_policy(policy: Option<&str>) -> Action {
    match policy.map(str::to_ascii_uppercase).as_deref() {
        Some("REJECT") | Some("REJECT-DROP") => Action::Block,
        _ => Action::Block,
    }
}

pub fn is_sinkhole_address(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok_and(|ip| {
        ip.is_unspecified() || ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import(format: SubscriptionFormat, text: &str) -> ImportReport {
        import_text(format, text, "source-a", "https://rules.example/list", "ads")
    }

    #[test]
    fn imports_supported_clash_rules_and_reports_unsupported_ones() {
        let report = import(SubscriptionFormat::Clash, "DOMAIN,ads.example,REJECT\nDOMAIN-SUFFIX,bad.example,REJECT\nPROCESS-NAME,app.exe,REJECT");
        assert_eq!(report.rules.len(), 2);
        assert_eq!(report.ignored.len(), 1);
        assert_eq!(report.rules[1].rule.kind, MatcherKind::Suffix);
    }

    #[test]
    fn imports_hosts_and_preserves_line_provenance() {
        let report = import(SubscriptionFormat::Hosts, "# comment\n0.0.0.0 ads.example\n127.0.0.1 tracker.example");
        assert_eq!(report.rules.len(), 2);
        assert_eq!(report.rules[0].source.source_line, 2);
        assert!(is_sinkhole_address("0.0.0.0"));
    }

    #[test]
    fn adblock_allow_rule_is_preserved() {
        let report = import(SubscriptionFormat::Adblock, "||ads.example^\n@@||safe.ads.example^\nexample.com##.banner");
        assert_eq!(report.rules.len(), 2);
        assert_eq!(report.rules[1].rule.action, Action::Allow);
        assert_eq!(report.ignored.len(), 1);
    }

    #[test]
    fn imports_ipv4_ipv6_and_cidr() {
        let report = import(SubscriptionFormat::IpList, "203.0.113.8\n2001:db8::1\n198.51.100.0/24");
        assert_eq!(report.rules.len(), 3);
        assert_eq!(report.rules[2].rule.kind, MatcherKind::Cidr);
    }
}
