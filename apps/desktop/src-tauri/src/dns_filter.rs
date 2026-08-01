use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cleanweb_rules::{
    DomainDecision, DomainRuleIndex, DomainRuleInput, DomainRuleTier, MatcherKind,
};
use hickory_proto::op::{Message, Metadata, ResponseCode};
use hickory_proto::rr::{
    rdata::{A, AAAA, CNAME},
    Name, RData, Record, RecordType,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::storage::AppState;

pub(crate) const CLEANWEB_DNS_LISTEN: &str = "127.0.0.1:19053";
const UDP_PACKET_SIZE: usize = 4096;
const SAFE_SEARCH_CNAME_TTL: u32 = 300;

struct DnsFilterConfig {
    domain_index: DomainRuleIndex,
    upstreams: Vec<String>,
    safe_search_enabled: bool,
    safe_search_mappings: HashMap<String, String>,
}

pub(crate) struct DnsFilterHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl DnsFilterHandle {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.send_to(&[0], CLEANWEB_DNS_LISTEN));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn start_dns_filter(state: &AppState) -> Result<(), String> {
    stop_dns_filter(state)?;
    let config = {
        let db = state.db.lock().map_err(|_| "数据库不可用")?;
        build_dns_filter_config(&db)?
    };
    let stop = Arc::new(AtomicBool::new(false));
    let socket = UdpSocket::bind(CLEANWEB_DNS_LISTEN)
        .map_err(|value| format!("无法启动 CleanWeb DNS 过滤服务：{value}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|value| format!("无法配置 CleanWeb DNS 过滤服务：{value}"))?;
    let thread_stop = Arc::clone(&stop);
    let db_path = state.db_path.clone();
    let join = thread::Builder::new()
        .name("cleanweb-dns-filter".into())
        .spawn(move || run_dns_filter(socket, config, db_path, thread_stop))
        .map_err(|value| format!("无法启动 CleanWeb DNS 过滤线程：{value}"))?;
    *state.dns_filter.lock().map_err(|_| "DNS 过滤状态不可用")? = Some(DnsFilterHandle {
        stop,
        join: Some(join),
    });
    Ok(())
}

pub(crate) fn stop_dns_filter(state: &AppState) -> Result<(), String> {
    if let Some(handle) = state
        .dns_filter
        .lock()
        .map_err(|_| "DNS 过滤状态不可用")?
        .take()
    {
        handle.stop();
    }
    Ok(())
}

fn run_dns_filter(
    socket: UdpSocket,
    config: DnsFilterConfig,
    db_path: PathBuf,
    stop: Arc<AtomicBool>,
) {
    let log_db = Connection::open(db_path).ok();
    let mut buffer = [0_u8; UDP_PACKET_SIZE];
    while !stop.load(Ordering::Acquire) {
        let Ok((len, peer)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        if let Some(response) = handle_dns_packet(&buffer[..len], &config, log_db.as_ref(), peer) {
            let _ = socket.send_to(&response, peer);
        }
    }
}

fn handle_dns_packet(
    packet: &[u8],
    config: &DnsFilterConfig,
    log_db: Option<&Connection>,
    _peer: SocketAddr,
) -> Option<Vec<u8>> {
    let message = Message::from_vec(packet).ok()?;
    let domain = message
        .queries
        .first()
        .map(|query| query.name().to_ascii())
        .map(|value| value.trim_end_matches('.').to_owned())?;
    if let Some(decision) = config
        .domain_index
        .decide(&domain)
        .filter(|decision| decision.blocked)
    {
        if let Some(db) = log_db {
            let _ = insert_dns_block_log(db, &domain, decision);
        }
        return blocked_response(&message);
    }
    if config.safe_search_enabled {
        if let Some(response) = safe_search_response(&message, config, &domain) {
            return Some(response);
        }
    }
    forward_dns_packet(packet, &config.upstreams).ok()
}

fn blocked_response(request: &Message) -> Option<Vec<u8>> {
    let mut response = Message::new(
        request.metadata.id,
        hickory_proto::op::MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NXDomain;
    response.add_queries(request.queries.iter().cloned());
    response.to_vec().ok()
}

fn safe_search_response(
    request: &Message,
    config: &DnsFilterConfig,
    domain: &str,
) -> Option<Vec<u8>> {
    let target = config.safe_search_mappings.get(domain)?;
    let query = request.queries.first()?;
    let answer = safe_search_answer(query.name().clone(), query.query_type(), target)?;
    let mut response = Message::new(
        request.metadata.id,
        hickory_proto::op::MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().cloned());
    response.add_answer(answer);
    response.to_vec().ok()
}

fn safe_search_answer(name: Name, query_type: RecordType, target: &str) -> Option<Record> {
    if let Ok(address) = target.parse::<IpAddr>() {
        return match (query_type, address) {
            (RecordType::A, IpAddr::V4(address)) => Some(Record::from_rdata(
                name,
                SAFE_SEARCH_CNAME_TTL,
                RData::A(A(address)),
            )),
            (RecordType::AAAA, IpAddr::V6(address)) => Some(Record::from_rdata(
                name,
                SAFE_SEARCH_CNAME_TTL,
                RData::AAAA(AAAA(address)),
            )),
            _ => None,
        };
    }
    let target = Name::from_ascii(target).ok()?;
    Some(Record::from_rdata(
        name,
        SAFE_SEARCH_CNAME_TTL,
        RData::CNAME(CNAME(target)),
    ))
}

fn forward_dns_packet(packet: &[u8], upstreams: &[String]) -> Result<Vec<u8>, std::io::Error> {
    let mut response = [0_u8; UDP_PACKET_SIZE];
    let mut last_error = None;
    for upstream in upstreams {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0")?;
        upstream_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        upstream_socket.send_to(packet, upstream)?;
        match upstream_socket.recv_from(&mut response) {
            Ok((len, _)) => return Ok(response[..len].to_vec()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("DNS upstream unavailable")))
}

fn build_dns_filter_config(db: &Connection) -> Result<DnsFilterConfig, String> {
    let settings = settings_map(db)?;
    let mut inputs = Vec::new();
    append_parent_domain_rules(db, &mut inputs)?;
    append_imported_domain_blocks(db, &settings, &mut inputs)?;
    Ok(DnsFilterConfig {
        domain_index: DomainRuleIndex::compile(inputs).map_err(|value| value.to_string())?,
        upstreams: configured_dns_upstreams(&settings),
        safe_search_enabled: settings
            .get("safe_search_enabled")
            .is_none_or(|value| value == "true"),
        safe_search_mappings: load_safe_search_mappings(db)?,
    })
}

fn configured_dns_upstreams(settings: &HashMap<String, String>) -> Vec<String> {
    settings
        .get("dns_upstreams")
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn append_parent_domain_rules(
    db: &Connection,
    inputs: &mut Vec<DomainRuleInput>,
) -> Result<(), String> {
    let mut statement = db
        .prepare(
            "SELECT kind,pattern,action FROM parent_rules
             WHERE enabled=1 AND kind IN ('exact','suffix') AND action IN ('block','allow')
             ORDER BY CASE action WHEN 'block' THEN 0 ELSE 1 END,created_at",
        )
        .map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    for (kind, pattern, action) in rows {
        let Some(kind) = domain_kind(&kind) else {
            continue;
        };
        inputs.push(DomainRuleInput {
            tier: if action == "allow" {
                DomainRuleTier::ManualAllow
            } else {
                DomainRuleTier::ManualBlock
            },
            kind,
            pattern,
        });
    }
    Ok(())
}

fn append_imported_domain_blocks(
    db: &Connection,
    settings: &std::collections::HashMap<String, String>,
    inputs: &mut Vec<DomainRuleInput>,
) -> Result<(), String> {
    let mut statement = db
        .prepare(
            "SELECT r.matcher_kind,r.pattern,r.category FROM imported_rules r
             JOIN subscriptions s ON s.id=r.subscription_id
             WHERE s.enabled=1 AND r.action='Block' AND r.matcher_kind IN ('Exact','Suffix')
             ORDER BY s.created_at,r.source_line",
        )
        .map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    for (kind, pattern, category) in rows {
        if !category_enabled(settings, &category) {
            continue;
        }
        let Some(kind) = imported_domain_kind(&kind) else {
            continue;
        };
        inputs.push(DomainRuleInput {
            tier: if is_security_category(&category) {
                DomainRuleTier::SecurityBlock
            } else {
                DomainRuleTier::Block
            },
            kind,
            pattern,
        });
    }
    Ok(())
}

fn category_enabled(settings: &std::collections::HashMap<String, String>, category: &str) -> bool {
    if category == "strict"
        && !settings
            .get("strict_mode_enabled")
            .is_some_and(|value| value == "true")
    {
        return false;
    }
    !settings
        .get(&format!("category.{category}"))
        .is_some_and(|value| value == "false")
}

fn load_safe_search_mappings(db: &Connection) -> Result<HashMap<String, String>, String> {
    let mut statement = db
        .prepare(
            "SELECT m.domain,m.target FROM safe_search_mappings m
             JOIN subscriptions s ON s.id=m.subscription_id
             WHERE s.enabled=1
             ORDER BY s.created_at,m.source_line",
        )
        .map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                normalize_domain(row.get::<_, String>(0)?),
                normalize_target(row.get::<_, String>(1)?),
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows.into_iter().collect())
}

fn normalize_domain(value: String) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_target(value: String) -> String {
    let value = value.trim().trim_end_matches('.');
    format!("{value}.")
}

fn settings_map(db: &Connection) -> Result<HashMap<String, String>, String> {
    let mut statement = db
        .prepare("SELECT key,value FROM settings")
        .map_err(error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<HashMap<_, _>>>()
        .map_err(error)?;
    Ok(rows)
}

fn domain_kind(value: &str) -> Option<MatcherKind> {
    match value {
        "exact" => Some(MatcherKind::Exact),
        "suffix" => Some(MatcherKind::Suffix),
        _ => None,
    }
}

fn imported_domain_kind(value: &str) -> Option<MatcherKind> {
    match value {
        "Exact" => Some(MatcherKind::Exact),
        "Suffix" => Some(MatcherKind::Suffix),
        _ => None,
    }
}

fn is_security_category(category: &str) -> bool {
    matches!(category, "fraud" | "phishing" | "malware")
}

fn insert_dns_block_log(
    db: &Connection,
    domain: &str,
    decision: DomainDecision,
) -> Result<(), String> {
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_millis() as i64;
    let domain_id = intern_access_log_string(db, domain)?;
    let rule_id = intern_access_log_string(db, "CleanWeb DNS filter")?;
    let category_id = intern_access_log_string(db, domain_decision_category(decision.tier))?;
    let process_id = intern_access_log_string(db, "CleanWeb DNS")?;
    let os_id = intern_access_log_string(db, std::env::consts::OS)?;
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let user_id = intern_access_log_string(db, &user)?;
    let route_id = intern_access_log_string(db, "REJECT")?;
    let connection_hash = dns_log_hash(domain, observed_at_ms);
    db.execute(
        "INSERT OR IGNORE INTO access_logs(connection_hash,observed_at_ms,domain_string_id,target_port,decision_code,rule_string_id,category_string_id,process_name_string_id,operating_system_string_id,system_user_string_id,route_string_id,repeat_count)
         VALUES(?1,?2,?3,53,1,?4,?5,?6,?7,?8,?9,1)",
        params![
            connection_hash,
            observed_at_ms,
            domain_id,
            rule_id,
            category_id,
            process_id,
            os_id,
            user_id,
            route_id
        ],
    )
    .map(|_| ())
    .map_err(error)
}

fn intern_access_log_string(db: &Connection, value: &str) -> Result<i64, String> {
    db.execute(
        "INSERT OR IGNORE INTO access_log_strings(value) VALUES(?1)",
        params![value],
    )
    .map_err(error)?;
    db.query_row(
        "SELECT id FROM access_log_strings WHERE value=?1",
        params![value],
        |row| row.get(0),
    )
    .optional()
    .map_err(error)?
    .ok_or_else(|| "访问日志字符串写入失败".into())
}

fn dns_log_hash(domain: &str, observed_at_ms: i64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"cleanweb-dns-filter");
    hasher.update(domain.as_bytes());
    hasher.update(observed_at_ms.to_be_bytes());
    hasher.finalize().to_vec()
}

fn domain_decision_category(tier: DomainRuleTier) -> &'static str {
    match tier {
        DomainRuleTier::SecurityBlock => "安全规则",
        DomainRuleTier::ManualBlock => "手动拦截",
        DomainRuleTier::ManualAllow => "手动放行",
        DomainRuleTier::Block => "内容规则",
    }
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use crate::storage::AppState;

    use hickory_proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RecordType},
    };

    use super::*;

    #[test]
    fn blocked_domains_return_nxdomain() {
        let config = DnsFilterConfig {
            domain_index: DomainRuleIndex::compile(vec![DomainRuleInput {
                tier: DomainRuleTier::Block,
                kind: MatcherKind::Suffix,
                pattern: "blocked.example".into(),
            }])
            .unwrap(),
            upstreams: Vec::new(),
            safe_search_enabled: true,
            safe_search_mappings: HashMap::new(),
        };
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("www.blocked.example.").unwrap(),
            RecordType::A,
        ));
        let response = handle_dns_packet(
            &request.to_vec().unwrap(),
            &config,
            None,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap();
        let message = Message::from_vec(&response).unwrap();

        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn safe_search_domains_return_google_cname() {
        let config = DnsFilterConfig {
            domain_index: DomainRuleIndex::default(),
            upstreams: Vec::new(),
            safe_search_enabled: true,
            safe_search_mappings: HashMap::from([(
                "www.google.com".into(),
                "forcesafesearch.google.com.".into(),
            )]),
        };
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("www.google.com.").unwrap(),
            RecordType::A,
        ));
        let response = handle_dns_packet(
            &request.to_vec().unwrap(),
            &config,
            None,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap();
        let message = Message::from_vec(&response).unwrap();

        assert_eq!(message.answers.len(), 1);
        assert_eq!(
            message.answers[0].data.to_string(),
            "forcesafesearch.google.com."
        );
    }

    #[test]
    fn safe_search_ip_targets_return_address_records() {
        let config = DnsFilterConfig {
            domain_index: DomainRuleIndex::default(),
            upstreams: Vec::new(),
            safe_search_enabled: true,
            safe_search_mappings: HashMap::from([("yandex.ru".into(), "213.180.193.56".into())]),
        };
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("yandex.ru.").unwrap(),
            RecordType::A,
        ));
        let response = handle_dns_packet(
            &request.to_vec().unwrap(),
            &config,
            None,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap();
        let message = Message::from_vec(&response).unwrap();

        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].data.to_string(), "213.180.193.56");
    }

    #[test]
    fn strict_imported_domain_blocks_follow_strict_mode_setting() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO subscriptions(id,kind,name,url,format,category,enabled)
                 VALUES('strict-source','rule','严格规则','https://example.test/strict.txt','clash','strict',1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line)
                 VALUES('strict-source','strict-1','Suffix','strict.example','Block','strict',1)",
                [],
            )
            .unwrap();
        }

        {
            let db = state.db.lock().unwrap();
            let config = build_dns_filter_config(&db).unwrap();
            assert!(config.domain_index.decide("www.strict.example").is_none());
        }

        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE settings SET value='true' WHERE key='strict_mode_enabled'",
                [],
            )
            .unwrap();
            let config = build_dns_filter_config(&db).unwrap();
            assert!(config
                .domain_index
                .decide("www.strict.example")
                .is_some_and(|decision| decision.blocked));
        }
    }

    #[test]
    fn entertainment_imported_domain_blocks_follow_category_setting() {
        let state = AppState::open(":memory:").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO subscriptions(id,kind,name,url,format,category,enabled)
                 VALUES('fun','rule','fun','https://x/fun.txt','clash','entertainment',1)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO imported_rules(subscription_id,rule_id,matcher_kind,pattern,action,category,source_line)
                 VALUES('fun','1','Suffix','game.example','Block','entertainment',1)",
                [],
            )
            .unwrap();
        }

        {
            let db = state.db.lock().unwrap();
            let config = build_dns_filter_config(&db).unwrap();
            assert!(config.domain_index.decide("www.game.example").is_none());
        }

        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE settings SET value='true' WHERE key='category.entertainment'",
                [],
            )
            .unwrap();
            let config = build_dns_filter_config(&db).unwrap();
            assert!(config
                .domain_index
                .decide("www.game.example")
                .is_some_and(|decision| decision.blocked));
        }
    }
}
