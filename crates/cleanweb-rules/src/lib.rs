use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    net::IpAddr,
    path::{Path, PathBuf},
};
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
    #[error("domain index I/O failed: {0}")]
    IndexIo(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision<'a> {
    pub action: Action,
    pub rule_id: &'a str,
    pub category: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRuleTier {
    SecurityBlock,
    ManualBlock,
    ManualAllow,
    Block,
}

#[derive(Debug, Clone)]
pub struct DomainRuleInput {
    pub tier: DomainRuleTier,
    pub kind: MatcherKind,
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainDecision {
    pub blocked: bool,
    pub tier: DomainRuleTier,
}

#[derive(Debug, Default)]
pub struct DomainRuleIndex {
    security_block: DomainMatcher,
    manual_block: DomainMatcher,
    manual_allow: DomainMatcher,
    block: DomainMatcher,
}

#[derive(Debug, Default)]
struct DomainMatcher {
    exact: Option<fst::Set<DomainFstData>>,
    suffix: Option<fst::Set<DomainFstData>>,
}

#[derive(Debug)]
enum DomainFstData {
    Owned(Vec<u8>),
    Mmap(MappedFile),
}

impl AsRef<[u8]> for DomainFstData {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mmap(mmap) => mmap.as_ref(),
        }
    }
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

    pub fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
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

impl DomainRuleIndex {
    pub fn compile(inputs: Vec<DomainRuleInput>) -> Result<Self, RuleError> {
        let mut builder = DomainRuleIndexBuilder::default();
        for input in inputs {
            builder.insert(input)?;
        }
        builder.build()
    }

    pub fn decide(&self, domain: &str) -> Option<DomainDecision> {
        let normalized = normalize_domain(domain).ok()?;
        for (tier, matcher, blocked) in [
            (DomainRuleTier::SecurityBlock, &self.security_block, true),
            (DomainRuleTier::ManualBlock, &self.manual_block, true),
            (DomainRuleTier::ManualAllow, &self.manual_allow, false),
            (DomainRuleTier::Block, &self.block, true),
        ] {
            if matcher.matches(&normalized) {
                return Some(DomainDecision { blocked, tier });
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.security_block.is_empty()
            && self.manual_block.is_empty()
            && self.manual_allow.is_empty()
            && self.block.is_empty()
    }

    pub fn load_mmap(paths: &DomainRuleIndexPaths) -> Result<Self, RuleError> {
        Ok(Self {
            security_block: DomainMatcher::load_mmap(
                &paths.security_block_exact,
                &paths.security_block_suffix,
            )?,
            manual_block: DomainMatcher::load_mmap(
                &paths.manual_block_exact,
                &paths.manual_block_suffix,
            )?,
            manual_allow: DomainMatcher::load_mmap(
                &paths.manual_allow_exact,
                &paths.manual_allow_suffix,
            )?,
            block: DomainMatcher::load_mmap(&paths.block_exact, &paths.block_suffix)?,
        })
    }
}

#[derive(Debug, Default)]
pub struct DomainRuleIndexBuilder {
    security_block: DomainMatcherBuilder,
    manual_block: DomainMatcherBuilder,
    manual_allow: DomainMatcherBuilder,
    block: DomainMatcherBuilder,
}

#[derive(Debug, Default)]
struct DomainMatcherBuilder {
    exact: Vec<String>,
    suffix: Vec<String>,
}

impl DomainRuleIndexBuilder {
    pub fn insert(&mut self, input: DomainRuleInput) -> Result<(), RuleError> {
        let normalized = normalize_domain(&input.pattern)?;
        match input.tier {
            DomainRuleTier::SecurityBlock => self.security_block.insert(input.kind, &normalized),
            DomainRuleTier::ManualBlock => self.manual_block.insert(input.kind, &normalized),
            DomainRuleTier::ManualAllow => self.manual_allow.insert(input.kind, &normalized),
            DomainRuleTier::Block => self.block.insert(input.kind, &normalized),
        }
        Ok(())
    }

    pub fn build(self) -> Result<DomainRuleIndex, RuleError> {
        Ok(DomainRuleIndex {
            security_block: self.security_block.build()?,
            manual_block: self.manual_block.build()?,
            manual_allow: self.manual_allow.build()?,
            block: self.block.build()?,
        })
    }

    pub fn build_to_files(self, paths: &DomainRuleIndexPaths) -> Result<(), RuleError> {
        self.security_block
            .write_to_files(&paths.security_block_exact, &paths.security_block_suffix)?;
        self.manual_block
            .write_to_files(&paths.manual_block_exact, &paths.manual_block_suffix)?;
        self.manual_allow
            .write_to_files(&paths.manual_allow_exact, &paths.manual_allow_suffix)?;
        self.block
            .write_to_files(&paths.block_exact, &paths.block_suffix)?;
        Ok(())
    }
}

impl DomainMatcherBuilder {
    fn insert(&mut self, kind: MatcherKind, pattern: &str) {
        match kind {
            MatcherKind::Exact => {
                self.exact.push(pattern.to_owned());
            }
            MatcherKind::Suffix => {
                self.suffix.push(reverse_domain(pattern));
            }
            _ => {}
        }
    }

    fn build(self) -> Result<DomainMatcher, RuleError> {
        Ok(DomainMatcher {
            exact: build_fst_set(self.exact)?,
            suffix: build_fst_set(self.suffix)?,
        })
    }

    fn write_to_files(self, exact_path: &Path, suffix_path: &Path) -> Result<(), RuleError> {
        write_fst_set(self.exact, exact_path)?;
        write_fst_set(self.suffix, suffix_path)?;
        Ok(())
    }
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        self.exact.as_ref().is_some_and(|set| set.contains(domain))
            || self
                .suffix
                .as_ref()
                .is_some_and(|set| suffix_set_matches(set, domain))
    }

    fn is_empty(&self) -> bool {
        self.exact.is_none() && self.suffix.is_none()
    }

    fn load_mmap(exact_path: &Path, suffix_path: &Path) -> Result<Self, RuleError> {
        Ok(Self {
            exact: load_fst_set_mmap(exact_path)?,
            suffix: load_fst_set_mmap(suffix_path)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DomainRuleIndexPaths {
    pub security_block_exact: PathBuf,
    pub security_block_suffix: PathBuf,
    pub manual_block_exact: PathBuf,
    pub manual_block_suffix: PathBuf,
    pub manual_allow_exact: PathBuf,
    pub manual_allow_suffix: PathBuf,
    pub block_exact: PathBuf,
    pub block_suffix: PathBuf,
}

fn build_fst_set(mut values: Vec<String>) -> Result<Option<fst::Set<DomainFstData>>, RuleError> {
    if values.is_empty() {
        return Ok(None);
    }
    values.sort_unstable();
    values.dedup();
    let mut builder = fst::SetBuilder::memory();
    builder
        .extend_iter(values)
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))?;
    let bytes = builder
        .into_inner()
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))?;
    fst::Set::new(DomainFstData::Owned(bytes))
        .map(Some)
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))
}

fn write_fst_set(mut values: Vec<String>, path: &Path) -> Result<(), RuleError> {
    values.sort_unstable();
    values.dedup();
    let file = File::create(path)?;
    let mut builder = fst::SetBuilder::new(file)
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))?;
    builder
        .extend_iter(values)
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))?;
    builder
        .finish()
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))
}

fn load_fst_set_mmap(path: &Path) -> Result<Option<fst::Set<DomainFstData>>, RuleError> {
    let data = MappedFile::open(path)?;
    if data.as_ref().is_empty() {
        return Ok(None);
    }
    fst::Set::new(DomainFstData::Mmap(data))
        .map(Some)
        .map_err(|_| RuleError::InvalidDomain("domain index".into()))
}

#[derive(Debug)]
enum MappedFile {
    #[cfg(unix)]
    Unix(UnixMappedFile),
    #[cfg(not(unix))]
    Owned(Vec<u8>),
}

impl MappedFile {
    fn open(path: &Path) -> Result<Self, std::io::Error> {
        #[cfg(unix)]
        {
            return UnixMappedFile::open(path).map(Self::Unix);
        }
        #[cfg(not(unix))]
        {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut File::open(path)?, &mut bytes)?;
            Ok(Self::Owned(bytes))
        }
    }
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(unix)]
            Self::Unix(file) => file.as_ref(),
            #[cfg(not(unix))]
            Self::Owned(bytes) => bytes,
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct UnixMappedFile {
    ptr: std::ptr::NonNull<libc::c_void>,
    len: usize,
}

#[cfg(unix)]
impl UnixMappedFile {
    fn open(path: &Path) -> Result<Self, std::io::Error> {
        use std::os::fd::AsRawFd;

        let file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot mmap an empty file",
            ));
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: std::ptr::NonNull::new(ptr).expect("mmap returned a non-null pointer"),
            len,
        })
    }
}

#[cfg(unix)]
impl AsRef<[u8]> for UnixMappedFile {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast(), self.len) }
    }
}

#[cfg(unix)]
impl Drop for UnixMappedFile {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr(), self.len);
        }
    }
}

#[cfg(unix)]
unsafe impl Send for UnixMappedFile {}

#[cfg(unix)]
unsafe impl Sync for UnixMappedFile {}

fn suffix_set_matches<D: AsRef<[u8]>>(set: &fst::Set<D>, domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    (0..labels.len()).any(|index| set.contains(reverse_labels(&labels[index..])))
}

fn reverse_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.split('.').collect();
    reverse_labels(&labels)
}

fn reverse_labels(labels: &[&str]) -> String {
    labels.iter().rev().copied().collect::<Vec<_>>().join(".")
}

pub fn take_early_network_block_rules<T, F>(rules: &mut Vec<T>, mut rule_line: F) -> Vec<T>
where
    F: FnMut(&T) -> Option<&str>,
{
    let mut early_rules = Vec::new();
    let mut remaining_rules = Vec::with_capacity(rules.len());
    for rule in rules.drain(..) {
        if rule_line(&rule).is_some_and(is_early_network_block_rule_line) {
            early_rules.push(rule);
        } else {
            remaining_rules.push(rule);
        }
    }
    *rules = remaining_rules;
    early_rules
}

pub fn is_early_network_block_rule_line(rule: &str) -> bool {
    let mut parts = rule.split(',');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(_) = parts.next() else {
        return false;
    };
    let Some(action) = parts.next() else {
        return false;
    };
    matches!(kind, "IP-CIDR" | "IP-CIDR6") && action == "REJECT"
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

    fn domain_rule(tier: DomainRuleTier, kind: MatcherKind, pattern: &str) -> DomainRuleInput {
        DomainRuleInput {
            tier,
            kind,
            pattern: pattern.into(),
        }
    }

    #[test]
    fn domain_index_matches_exact_and_suffix_rules() {
        let index = DomainRuleIndex::compile(vec![
            domain_rule(DomainRuleTier::Block, MatcherKind::Suffix, "example.com"),
            domain_rule(
                DomainRuleTier::ManualAllow,
                MatcherKind::Exact,
                "safe.example.com",
            ),
        ])
        .unwrap();

        assert_eq!(
            index.decide("a.example.com"),
            Some(DomainDecision {
                blocked: true,
                tier: DomainRuleTier::Block
            })
        );
        assert_eq!(
            index.decide("safe.example.com"),
            Some(DomainDecision {
                blocked: false,
                tier: DomainRuleTier::ManualAllow
            })
        );
        assert_eq!(index.decide("notexample.com"), None);
    }

    #[test]
    fn security_blocks_beat_manual_allow() {
        let index = DomainRuleIndex::compile(vec![
            domain_rule(
                DomainRuleTier::SecurityBlock,
                MatcherKind::Suffix,
                "bad.example",
            ),
            domain_rule(
                DomainRuleTier::ManualAllow,
                MatcherKind::Suffix,
                "bad.example",
            ),
        ])
        .unwrap();

        assert_eq!(
            index.decide("www.bad.example"),
            Some(DomainDecision {
                blocked: true,
                tier: DomainRuleTier::SecurityBlock
            })
        );
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

    #[test]
    fn identifies_early_network_block_rule_lines() {
        assert!(is_early_network_block_rule_line(
            "IP-CIDR,8.8.8.8,REJECT,no-resolve"
        ));
        assert!(is_early_network_block_rule_line(
            "IP-CIDR6,fd00::/8,REJECT,no-resolve"
        ));
        assert!(!is_early_network_block_rule_line(
            "IP-CIDR,8.8.8.8/32,DIRECT,no-resolve"
        ));
        assert!(!is_early_network_block_rule_line(
            "DOMAIN-SUFFIX,example.com,REJECT"
        ));
    }

    #[test]
    fn splits_early_network_block_rules_without_reordering_the_rest() {
        let mut rules = vec![
            "DOMAIN-SUFFIX,blocked.example,REJECT".to_string(),
            "IP-CIDR,8.8.8.8,REJECT,no-resolve".to_string(),
            "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve".to_string(),
            "IP-CIDR6,fd00::/8,REJECT,no-resolve".to_string(),
            "MATCH,DIRECT".to_string(),
        ];

        let early = take_early_network_block_rules(&mut rules, |rule| Some(rule.as_str()));

        assert_eq!(
            early,
            vec![
                "IP-CIDR,8.8.8.8,REJECT,no-resolve".to_string(),
                "IP-CIDR6,fd00::/8,REJECT,no-resolve".to_string(),
            ]
        );
        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,blocked.example,REJECT".to_string(),
                "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve".to_string(),
                "MATCH,DIRECT".to_string(),
            ]
        );
    }
}
