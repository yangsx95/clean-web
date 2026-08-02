use std::sync::{LazyLock, Mutex};

use cleanweb_rules::{Action, MatcherKind, RuleInput, RuleSet};
use cleanweb_subscriptions::{import_text, SubscriptionFormat};
use jni::{
    objects::{JByteArray, JObject, JString},
    sys::{jbyteArray, jstring},
    JNIEnv,
};
use serde::Deserialize;

static DNS_ENGINE: LazyLock<Mutex<MobileDnsEngine>> =
    LazyLock::new(|| Mutex::new(MobileDnsEngine::default()));

#[derive(Default)]
struct MobileDnsEngine {
    rules: RuleSet,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobilePolicy {
    settings: Option<MobileSettings>,
    parent_rules: Option<Vec<MobileParentRule>>,
    subscriptions: Option<Vec<MobileSubscription>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobileSettings {
    strict_mode_enabled: Option<bool>,
    categories: Option<std::collections::HashMap<String, bool>>,
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
    enabled: bool,
}

impl MobileDnsEngine {
    fn update_policy(&mut self, policy_json: &str) -> Result<(), String> {
        let policy: MobilePolicy = serde_json::from_str(policy_json)
            .map_err(|value| format!("Android DNS policy payload is invalid JSON: {value}"))?;
        self.rules = RuleSet::compile(policy_rules(&policy)).map_err(|value| value.to_string())?;
        Ok(())
    }

    fn handle_dns_query(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let query = DnsQuestion::parse(packet)?;
        let decision = self.rules.decide(Some(&query.domain), None)?;
        if decision.action == Action::Block {
            return Some(blocked_response(packet, query.question_end));
        }
        None
    }
}

fn policy_rules(policy: &MobilePolicy) -> Vec<RuleInput> {
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
    rules
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
        Some(Self {
            domain: labels.join("."),
            question_end: offset + 4,
        })
    }
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
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);
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
}
