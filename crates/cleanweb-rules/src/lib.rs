use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Block,
    Proxy,
    SystemRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatcherKind {
    Exact,
    Suffix,
    Contains,
    Wildcard,
    Regex,
    Ip,
    Cidr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInput {
    pub id: String,
    pub action: Action,
    pub priority: u16,
    pub kind: MatcherKind,
    pub pattern: String,
    pub category: String,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub source: RuleInput,
    matcher: Matcher,
}

#[derive(Debug)]
enum Matcher {
    Domain(String),
    Contains(String),
    Pattern(Regex),
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid domain pattern: {0}")]
    InvalidDomain(String),
    #[error("invalid regular expression: {0}")]
    InvalidRegex(#[from] regex::Error),
    #[error("invalid IP or CIDR: {0}")]
    InvalidNetwork(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision<'a> {
    pub action: Action,
    pub rule_id: &'a str,
    pub category: &'a str,
}

impl CompiledRule {
    pub fn compile(mut source: RuleInput) -> Result<Self, RuleError> {
        let matcher = match source.kind {
            MatcherKind::Exact | MatcherKind::Suffix => {
                source.pattern = normalize_domain(&source.pattern)?;
                Matcher::Domain(source.pattern.clone())
            }
            MatcherKind::Contains => {
                let value = source.pattern.trim().to_ascii_lowercase();
                if value.is_empty() {
                    return Err(RuleError::InvalidDomain(source.pattern));
                }
                source.pattern = value.clone();
                Matcher::Contains(value)
            }
            MatcherKind::Wildcard => Matcher::Pattern(wildcard_regex(&source.pattern)?),
            MatcherKind::Regex => Matcher::Pattern(
                RegexBuilder::new(&source.pattern)
                    .case_insensitive(true)
                    .build()?,
            ),
            MatcherKind::Ip => Matcher::Ip(
                source
                    .pattern
                    .parse()
                    .map_err(|_| RuleError::InvalidNetwork(source.pattern.clone()))?,
            ),
            MatcherKind::Cidr => Matcher::Cidr(
                source
                    .pattern
                    .parse()
                    .map_err(|_| RuleError::InvalidNetwork(source.pattern.clone()))?,
            ),
        };
        Ok(Self { source, matcher })
    }

    fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        match (&self.matcher, self.source.kind.clone()) {
            (Matcher::Domain(expected), MatcherKind::Exact) => {
                domain.is_some_and(|d| d == expected)
            }
            (Matcher::Domain(expected), MatcherKind::Suffix) => {
                domain.is_some_and(|d| d == expected || d.ends_with(&format!(".{expected}")))
            }
            (Matcher::Contains(value), _) => domain.is_some_and(|d| d.contains(value)),
            (Matcher::Pattern(pattern), _) => domain.is_some_and(|d| pattern.is_match(d)),
            (Matcher::Ip(expected), _) => ip.is_some_and(|value| value == *expected),
            (Matcher::Cidr(network), _) => ip.is_some_and(|value| network.contains(&value)),
            _ => false,
        }
    }
}

#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn compile(inputs: Vec<RuleInput>) -> Result<Self, RuleError> {
        let mut rules = inputs
            .into_iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>, _>>()?;
        rules.sort_by_key(|rule| rule.source.priority);
        Ok(Self { rules })
    }

    pub fn decide(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Option<Decision<'_>> {
        let normalized = domain.and_then(|value| normalize_domain(value).ok());
        self.rules
            .iter()
            .find(|rule| rule.matches(normalized.as_deref(), ip))
            .map(|rule| Decision {
                action: rule.source.action,
                rule_id: &rule.source.id,
                category: &rule.source.category,
            })
    }
}

fn normalize_domain(value: &str) -> Result<String, RuleError> {
    let trimmed = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.contains('/') {
        return Err(RuleError::InvalidDomain(value.into()));
    }
    idna::domain_to_ascii(&trimmed).map_err(|_| RuleError::InvalidDomain(value.into()))
}

fn wildcard_regex(value: &str) -> Result<Regex, RuleError> {
    let mut pattern = String::from("^");
    for ch in value.trim().to_ascii_lowercase().chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            other => pattern.push_str(&regex::escape(&other.to_string())),
        }
    }
    pattern.push('$');
    Ok(RegexBuilder::new(&pattern).case_insensitive(true).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        priority: u16,
        kind: MatcherKind,
        pattern: &str,
        action: Action,
    ) -> RuleInput {
        RuleInput {
            id: id.into(),
            priority,
            kind,
            pattern: pattern.into(),
            action,
            category: "test".into(),
        }
    }

    #[test]
    fn suffix_matches_domain_and_children_but_not_lookalikes() {
        let set = RuleSet::compile(vec![rule(
            "adult",
            10,
            MatcherKind::Suffix,
            "example.com",
            Action::Block,
        )])
        .unwrap();
        assert!(set.decide(Some("a.example.com"), None).is_some());
        assert!(set.decide(Some("notexample.com"), None).is_none());
    }

    #[test]
    fn contains_and_regex_are_supported() {
        let set = RuleSet::compile(vec![
            rule("contains", 20, MatcherKind::Contains, "porn", Action::Block),
            rule(
                "regex",
                30,
                MatcherKind::Regex,
                r"(^|\.)bad\d+\.test$",
                Action::Block,
            ),
        ])
        .unwrap();
        assert_eq!(
            set.decide(Some("notporn.example"), None).unwrap().rule_id,
            "contains"
        );
        assert_eq!(
            set.decide(Some("bad42.test"), None).unwrap().rule_id,
            "regex"
        );
    }

    #[test]
    fn lower_priority_number_wins() {
        let set = RuleSet::compile(vec![
            rule(
                "parent-allow",
                40,
                MatcherKind::Exact,
                "example.com",
                Action::Allow,
            ),
            rule(
                "subscription-block",
                70,
                MatcherKind::Exact,
                "example.com",
                Action::Block,
            ),
        ])
        .unwrap();
        assert_eq!(
            set.decide(Some("example.com"), None).unwrap().action,
            Action::Allow
        );
    }

    #[test]
    fn cidr_blocks_matching_ip() {
        let set = RuleSet::compile(vec![rule(
            "network",
            20,
            MatcherKind::Cidr,
            "203.0.113.0/24",
            Action::Block,
        )])
        .unwrap();
        assert!(set
            .decide(None, Some("203.0.113.9".parse().unwrap()))
            .is_some());
        assert!(set
            .decide(None, Some("198.51.100.9".parse().unwrap()))
            .is_none());
    }
}
