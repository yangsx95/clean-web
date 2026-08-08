use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{LazyLock, Mutex},
};

use cleanweb_rules::{Action, MatcherKind, RuleInput, RuleSet};
use cleanweb_subscriptions::{import_safe_search_mappings, import_text, SubscriptionFormat};
use jni::{
    objects::{JByteArray, JObject, JString},
    sys::{jbyteArray, jstring},
    JNIEnv,
};
use serde::Deserialize;

use crate::mobile_subscription_store;

static DNS_ENGINE: LazyLock<Mutex<MobileDnsEngine>> =
    LazyLock::new(|| Mutex::new(MobileDnsEngine::default()));
const SAFE_SEARCH_CNAME_TTL: u32 = 300;

#[derive(Default)]
struct MobileDnsEngine {
    rules: RuleSet,
    safe_search_enabled: bool,
    safe_search_mappings: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobilePolicy {
    settings: Option<MobileSettings>,
    parent_rules: Option<Vec<MobileParentRule>>,
    subscriptions: Option<Vec<MobileSubscription>>,
    subscription_store_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobileSettings {
    safe_search_enabled: Option<bool>,
    strict_mode_enabled: Option<bool>,
    categories: Option<HashMap<String, bool>>,
}

#[derive(Debug, Deserialize)]
struct MobileParentRule {
    action: String,
    kind: String,
    pattern: String,
    category: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct MobileSubscription {
    id: String,
    category: Option<String>,
    format: Option<String>,
    enabled: bool,
}

impl MobileDnsEngine {
    fn update_policy(&mut self, policy_json: &str) -> Result<(), String> {
        let policy: MobilePolicy = serde_json::from_str(policy_json)
            .map_err(|value| format!("Android DNS policy payload is invalid JSON: {value}"))?;
        self.rules = RuleSet::compile(policy_rules(&policy)?).map_err(|value| value.to_string())?;
        self.safe_search_enabled = policy
            .settings
            .as_ref()
            .and_then(|settings| settings.safe_search_enabled)
            .unwrap_or(true);
        self.safe_search_mappings = if self.safe_search_enabled {
            safe_search_mappings(&policy)?
        } else {
            HashMap::new()
        };
        Ok(())
    }

    fn handle_dns_query(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let query = DnsQuestion::parse(packet)?;
        if self
            .rules
            .decide(Some(&query.domain), None)
            .is_some_and(|decision| decision.action == Action::Block)
        {
            return Some(blocked_response(packet, query.question_end));
        }
        if self.safe_search_enabled {
            if let Some(target) = self.safe_search_mappings.get(&query.domain) {
                return safe_search_response(packet, &query, target);
            }
        }
        None
    }
}

fn policy_rules(policy: &MobilePolicy) -> Result<Vec<RuleInput>, String> {
    let mut rules = Vec::new();
    if let Some(parent_rules) = &policy.parent_rules {
        for (index, rule) in parent_rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let Some(kind) = matcher_kind(&rule.kind) else {
                continue;
            };
            let Some(action) = action(&rule.action) else {
                continue;
            };
            rules.push(RuleInput {
                id: format!("mobile:parent:{index}"),
                action,
                priority: if action == Action::Block { 20 } else { 30 },
                kind,
                pattern: rule.pattern.clone(),
                category: rule.category.clone(),
            });
        }
    }

    append_bundled_rules(policy, &mut rules);
    append_stored_rules(policy, &mut rules)?;
    Ok(rules)
}

fn append_bundled_rules(policy: &MobilePolicy, rules: &mut Vec<RuleInput>) {
    let strict_enabled = policy
        .settings
        .as_ref()
        .and_then(|settings| settings.strict_mode_enabled)
        .unwrap_or(false);
    let categories = policy
        .settings
        .as_ref()
        .and_then(|settings| settings.categories.as_ref());

    for source in bundled_sources() {
        if source.strict_only && !strict_enabled {
            continue;
        }
        if categories
            .and_then(|values| values.get(source.category))
            .is_some_and(|enabled| !enabled)
        {
            continue;
        }
        if !subscription_enabled(policy, source.subscription_id, source.category) {
            continue;
        }
        let report = import_text(
            SubscriptionFormat::Clash,
            source.text,
            source.subscription_id,
            source.url,
            source.category,
        );
        for imported in report.rules {
            if matches!(
                imported.rule.kind,
                MatcherKind::Exact
                    | MatcherKind::Suffix
                    | MatcherKind::Contains
                    | MatcherKind::Wildcard
                    | MatcherKind::Regex
            ) && imported.rule.action == Action::Block
            {
                rules.push(RuleInput {
                    priority: if is_security_category(source.category) {
                        10
                    } else {
                        70
                    },
                    ..imported.rule
                });
            }
        }
    }
}

fn append_stored_rules(policy: &MobilePolicy, rules: &mut Vec<RuleInput>) -> Result<(), String> {
    let Some(store_dir) = policy.subscription_store_dir.as_deref().map(Path::new) else {
        return Ok(());
    };
    let Some(subscriptions) = &policy.subscriptions else {
        return Ok(());
    };
    for subscription in subscriptions
        .iter()
        .filter(|item| item.enabled && item.format.as_deref() != Some("safe-search"))
    {
        for mut rule in
            mobile_subscription_store::read_subscription_rules(store_dir, &subscription.id)?
        {
            if let Some(category) = &subscription.category {
                rule.category = category.clone();
            }
            rules.push(rule);
        }
    }
    Ok(())
}

fn safe_search_mappings(policy: &MobilePolicy) -> Result<HashMap<String, String>, String> {
    let mut mappings = HashMap::new();
    if subscription_enabled(policy, "default:cleanweb:safe-search", "custom") {
        let report = import_safe_search_mappings(include_str!(
            "../../../../resources/rules/cleanweb-safe-search.yaml"
        ))?;
        for mapping in report.mappings {
            mappings.insert(mapping.domain, mapping.target);
        }
    }
    if let Some(store_dir) = policy.subscription_store_dir.as_deref().map(Path::new) {
        for subscription in policy
            .subscriptions
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|item| item.enabled && item.format.as_deref() == Some("safe-search"))
        {
            for mapping in
                mobile_subscription_store::read_safe_search_mappings(store_dir, &subscription.id)?
            {
                mappings.insert(mapping.domain, mapping.target);
            }
        }
    }
    Ok(mappings)
}

fn subscription_enabled(policy: &MobilePolicy, id: &str, category: &str) -> bool {
    policy
        .subscriptions
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.id == id))
        .map(|item| {
            item.enabled
                && item
                    .category
                    .as_deref()
                    .is_none_or(|value| value == category || value == "strict")
        })
        .unwrap_or(true)
}

struct BundledSource {
    subscription_id: &'static str,
    category: &'static str,
    url: &'static str,
    text: &'static str,
    strict_only: bool,
}

fn bundled_sources() -> Vec<BundledSource> {
    vec![
        BundledSource {
            subscription_id: "default:cleanweb:adult-supplement",
            category: "pornography",
            url: "bundled://cleanweb-adult-supplement.clash",
            text: include_str!("../../../../resources/rules/cleanweb-adult-supplement.clash"),
            strict_only: false,
        },
        BundledSource {
            subscription_id: "default:cleanweb:security-supplement",
            category: "phishing",
            url: "bundled://cleanweb-security-supplement.clash",
            text: include_str!("../../../../resources/rules/cleanweb-security-supplement.clash"),
            strict_only: false,
        },
        BundledSource {
            subscription_id: "default:cleanweb:strict-adult-keywords",
            category: "strict",
            url: "bundled://cleanweb-strict-adult-keywords.clash",
            text: include_str!("../../../../resources/rules/cleanweb-strict-adult-keywords.clash"),
            strict_only: true,
        },
        BundledSource {
            subscription_id: "default:cleanweb:strict-gambling-keywords",
            category: "strict",
            url: "bundled://cleanweb-strict-gambling-keywords.clash",
            text: include_str!(
                "../../../../resources/rules/cleanweb-strict-gambling-keywords.clash"
            ),
            strict_only: true,
        },
        BundledSource {
            subscription_id: "default:cleanweb:strict-platforms",
            category: "strict",
            url: "bundled://cleanweb-strict-platforms.clash",
            text: include_str!("../../../../resources/rules/cleanweb-strict-platforms.clash"),
            strict_only: true,
        },
        BundledSource {
            subscription_id: "local:cleanweb:entertainment-short-video",
            category: "entertainment",
            url: "bundled://cleanweb-entertainment-short-video.clash",
            text: include_str!(
                "../../../../resources/rules/cleanweb-entertainment-short-video.clash"
            ),
            strict_only: false,
        },
        BundledSource {
            subscription_id: "local:cleanweb:entertainment-social",
            category: "entertainment",
            url: "bundled://cleanweb-entertainment-social.clash",
            text: include_str!("../../../../resources/rules/cleanweb-entertainment-social.clash"),
            strict_only: false,
        },
        BundledSource {
            subscription_id: "local:cleanweb:entertainment-games",
            category: "entertainment",
            url: "bundled://cleanweb-entertainment-games.clash",
            text: include_str!("../../../../resources/rules/cleanweb-entertainment-games.clash"),
            strict_only: false,
        },
    ]
}

fn matcher_kind(value: &str) -> Option<MatcherKind> {
    match value.to_ascii_lowercase().as_str() {
        "exact" => Some(MatcherKind::Exact),
        "suffix" => Some(MatcherKind::Suffix),
        "contains" => Some(MatcherKind::Contains),
        "wildcard" => Some(MatcherKind::Wildcard),
        "regex" => Some(MatcherKind::Regex),
        _ => None,
    }
}

fn action(value: &str) -> Option<Action> {
    match value {
        "block" => Some(Action::Block),
        "allow" => Some(Action::Allow),
        _ => None,
    }
}

fn is_security_category(category: &str) -> bool {
    matches!(category, "fraud" | "phishing" | "malware")
}

struct DnsQuestion {
    domain: String,
    question_end: usize,
    query_type: u16,
    query_class: u16,
}

impl DnsQuestion {
    fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 12 || read_u16(packet, 4)? == 0 {
            return None;
        }
        let mut offset = 12;
        let mut labels = Vec::new();
        while offset < packet.len() {
            let len = *packet.get(offset)? as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            if len & 0xc0 != 0 || len > 63 || offset + len > packet.len() {
                return None;
            }
            let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
            labels.push(label.to_owned());
            offset += len;
        }
        if labels.is_empty() || offset + 4 > packet.len() {
            return None;
        }
        let query_type = read_u16(packet, offset)?;
        let query_class = read_u16(packet, offset + 2)?;
        Some(Self {
            domain: labels.join("."),
            question_end: offset + 4,
            query_type,
            query_class,
        })
    }
}

fn safe_search_response(request: &[u8], query: &DnsQuestion, target: &str) -> Option<Vec<u8>> {
    if let Ok(address) = target.parse::<IpAddr>() {
        return match (query.query_type, address) {
            (1, IpAddr::V4(address)) => {
                Some(answer_response(request, query, &[DnsAnswer::A(address)]))
            }
            (28, IpAddr::V6(address)) => {
                Some(answer_response(request, query, &[DnsAnswer::Aaaa(address)]))
            }
            _ => None,
        };
    }
    Some(answer_response(
        request,
        query,
        &[DnsAnswer::Cname(target.to_owned())],
    ))
}

enum DnsAnswer {
    Cname(String),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
}

fn answer_response(request: &[u8], query: &DnsQuestion, answers: &[DnsAnswer]) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.question_end + 96);
    response.extend_from_slice(&request[0..2]);
    let request_flags = read_u16(request, 2).unwrap_or(0);
    let recursion_desired = request_flags & 0x0100;
    write_u16(&mut response, 0x8000 | recursion_desired | 0x0080);
    response.extend_from_slice(&request[4..6]);
    write_u16(&mut response, answers.len() as u16);
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&request[12..query.question_end]);
    for answer in answers {
        response.extend_from_slice(&[0xc0, 0x0c]);
        match answer {
            DnsAnswer::Cname(target) => {
                let encoded = encode_dns_name(target).unwrap_or_default();
                write_u16(&mut response, 5);
                write_u16(&mut response, query.query_class);
                write_u32(&mut response, SAFE_SEARCH_CNAME_TTL);
                write_u16(&mut response, encoded.len() as u16);
                response.extend_from_slice(&encoded);
            }
            DnsAnswer::A(address) => {
                write_u16(&mut response, 1);
                write_u16(&mut response, query.query_class);
                write_u32(&mut response, SAFE_SEARCH_CNAME_TTL);
                write_u16(&mut response, 4);
                response.extend_from_slice(&address.octets());
            }
            DnsAnswer::Aaaa(address) => {
                write_u16(&mut response, 28);
                write_u16(&mut response, query.query_class);
                write_u32(&mut response, SAFE_SEARCH_CNAME_TTL);
                write_u16(&mut response, 16);
                response.extend_from_slice(&address.octets());
            }
        }
    }
    response
}

fn encode_dns_name(domain: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Some(output)
}

fn blocked_response(request: &[u8], question_end: usize) -> Vec<u8> {
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&request[0..2]);
    let request_flags = read_u16(request, 2).unwrap_or(0);
    let recursion_desired = request_flags & 0x0100;
    write_u16(&mut response, 0x8000 | recursion_desired | 0x0080 | 0x0003);
    response.extend_from_slice(&request[4..6]);
    response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..question_end]);
    response
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebDnsEngine_updatePolicy(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    policy_json: JString<'_>,
) -> jstring {
    let policy = match env.get_string(&policy_json) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(error) => return jni_string(&mut env, &error.to_string()),
    };
    match DNS_ENGINE
        .lock()
        .map_err(|_| "Android DNS engine lock is unavailable".to_string())
        .and_then(|mut engine| engine.update_policy(&policy))
    {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => jni_string(&mut env, &error),
    }
}

#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebDnsEngine_handleDnsQuery(
    env: JNIEnv<'_>,
    _object: JObject<'_>,
    query: JByteArray<'_>,
) -> jbyteArray {
    handle_dns_query_jni(env, query).unwrap_or(std::ptr::null_mut())
}

fn handle_dns_query_jni(env: JNIEnv<'_>, query: JByteArray<'_>) -> Option<jbyteArray> {
    let query = env.convert_byte_array(query).ok()?;
    let response = DNS_ENGINE.lock().ok()?.handle_dns_query(&query)?;
    env.byte_array_from_slice(&response)
        .ok()
        .map(|value| value.into_raw())
}

fn jni_string(env: &mut JNIEnv<'_>, value: &str) -> jstring {
    env.new_string(value)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(domain: &str) -> Vec<u8> {
        typed_query(domain, 1)
    }

    fn typed_query(domain: &str, query_type: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&query_type.to_be_bytes());
        packet.extend_from_slice(&[0, 1]);
        packet
    }

    #[test]
    fn blocks_parent_rule_domains_with_nxdomain() {
        let mut engine = MobileDnsEngine::default();
        engine
            .update_policy(
                r#"{"parentRules":[{"action":"block","kind":"suffix","pattern":"blocked.example","category":"test","enabled":true}]}"#,
            )
            .unwrap();
        let response = engine
            .handle_dns_query(&query("www.blocked.example"))
            .unwrap();
        assert_eq!(response[0..2], [0x12, 0x34]);
        assert_eq!(read_u16(&response, 2).unwrap() & 0x000f, 3);
        assert_eq!(read_u16(&response, 6).unwrap(), 0);
    }

    #[test]
    fn disabled_parent_rules_are_allowed() {
        let mut engine = MobileDnsEngine::default();
        engine
            .update_policy(
                r#"{"parentRules":[{"action":"block","kind":"suffix","pattern":"blocked.example","category":"test","enabled":false}]}"#,
            )
            .unwrap();
        assert!(engine
            .handle_dns_query(&query("www.blocked.example"))
            .is_none());
    }

    #[test]
    fn safe_search_domains_return_cname_answers() {
        let mut engine = MobileDnsEngine::default();
        engine
            .update_policy(r#"{"settings":{"safeSearchEnabled":true}}"#)
            .unwrap();
        let response = engine.handle_dns_query(&query("www.google.com")).unwrap();
        assert_eq!(response[0..2], [0x12, 0x34]);
        assert_eq!(read_u16(&response, 6).unwrap(), 1);
        assert_eq!(
            read_u16(&response, query("www.google.com").len() + 2).unwrap(),
            5
        );
        assert!(response
            .windows("forcesafesearch".len())
            .any(|value| value == b"forcesafesearch"));
    }

    #[test]
    fn safe_search_ip_targets_return_address_answers() {
        let mut engine = MobileDnsEngine::default();
        engine
            .update_policy(r#"{"settings":{"safeSearchEnabled":true}}"#)
            .unwrap();
        let response = engine.handle_dns_query(&query("yandex.com")).unwrap();
        assert_eq!(read_u16(&response, 6).unwrap(), 1);
        assert_eq!(
            read_u16(&response, query("yandex.com").len() + 2).unwrap(),
            1
        );
        assert!(response.ends_with(&[213, 180, 193, 56]));
        assert!(engine
            .handle_dns_query(&typed_query("yandex.com", 28))
            .is_none());
    }
}
