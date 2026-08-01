use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyring::{Entry, Error as KeyringError};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::sync::OnceLock;

const LEGACY_ENVELOPE_PREFIX: &str = "cw1:aes-256-gcm:";
const ENVELOPE_PREFIX: &str = "cw2:aes-256-gcm:";
#[cfg(any(test, debug_assertions))]
const KEY_SOURCE_DEBUG: &str = "debug";
const KEY_SOURCE_KEYCHAIN: &str = "keychain";
const KEYCHAIN_SERVICE: &str = "CleanWeb";
const KEYCHAIN_ACCOUNT: &str = "proxy-payload-key";
#[cfg(test)]
const TEST_KEY_ENV: &str = "CLEANWEB_TEST_PROXY_KEY_B64";
#[cfg(any(test, debug_assertions))]
const DEBUG_KEY_PATH_ENV: &str = "CLEANWEB_DEBUG_PROXY_KEY_PATH";

static PROXY_PAYLOAD_KEY: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
static KEYCHAIN_PROXY_PAYLOAD_KEY: OnceLock<Result<[u8; 32], String>> = OnceLock::new();

struct DecryptParts {
    key: [u8; 32],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[cfg(test)]
pub(crate) fn test_key_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn encrypt_proxy_payload(plaintext: &str) -> Result<String, String> {
    let key = load_or_create_key()?;
    encrypt_proxy_payload_with_key(plaintext, &key, current_key_source())
}

fn encrypt_proxy_payload_with_key(
    plaintext: &str,
    key: &[u8; 32],
    key_source: &str,
) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "代理加密密钥无效")?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| "代理加密 nonce 无效")?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "代理订阅加密失败")?;
    Ok(format!(
        "{ENVELOPE_PREFIX}{key_source}:{}:{}",
        STANDARD.encode(nonce_bytes),
        STANDARD.encode(ciphertext)
    ))
}

pub fn decrypt_proxy_payload(envelope: &str) -> Result<String, String> {
    if !is_encrypted_proxy_payload(envelope) {
        return Err("代理订阅载荷不是 CleanWeb 密文".into());
    }
    let parts = decrypt_parts(envelope)?;
    decrypt_with_key(&parts.key, parts.nonce, parts.ciphertext)
}

fn decrypt_parts(envelope: &str) -> Result<DecryptParts, String> {
    if let Some(body) = envelope.strip_prefix(ENVELOPE_PREFIX) {
        let (key_source, rest) = body
            .split_once(':')
            .ok_or_else(|| "代理订阅密文格式无效".to_string())?;
        let key = load_key_for_source(key_source)?;
        let (nonce, ciphertext) = rest
            .split_once(':')
            .ok_or_else(|| "代理订阅密文格式无效".to_string())?;
        return Ok(DecryptParts {
            key,
            nonce: decode_nonce(nonce)?,
            ciphertext: decode_ciphertext(ciphertext)?,
        });
    }

    if let Some(body) = envelope.strip_prefix(LEGACY_ENVELOPE_PREFIX) {
        let key = load_or_create_keychain_key()?;
        let (nonce, ciphertext) = body
            .split_once(':')
            .ok_or_else(|| "代理订阅密文格式无效".to_string())?;
        return Ok(DecryptParts {
            key,
            nonce: decode_nonce(nonce)?,
            ciphertext: decode_ciphertext(ciphertext)?,
        });
    }

    Err("代理订阅密文格式无效".into())
}

fn decode_nonce(nonce: &str) -> Result<Vec<u8>, String> {
    let nonce = STANDARD
        .decode(nonce)
        .map_err(|_| "代理订阅密文 nonce 无效")?;
    if nonce.len() != 12 {
        return Err("代理订阅密文 nonce 长度无效".into());
    }
    Ok(nonce)
}

fn decode_ciphertext(ciphertext: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(ciphertext)
        .map_err(|_| "代理订阅密文内容无效".to_string())
}

fn decrypt_with_key(key: &[u8; 32], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "代理加密密钥无效")?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| "代理订阅密文 nonce 无效")?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| "代理订阅解密失败")?;
    String::from_utf8(plaintext).map_err(|_| "代理订阅明文不是有效UTF-8文本".into())
}

pub fn is_encrypted_proxy_payload(value: &str) -> bool {
    value.starts_with(ENVELOPE_PREFIX) || value.starts_with(LEGACY_ENVELOPE_PREFIX)
}

pub fn encrypt_existing_proxy_payloads(db: &mut Connection) -> Result<usize, String> {
    let plaintext_rows = {
        let mut statement = db
            .prepare("SELECT subscription_id,payload FROM proxy_payloads")
            .map_err(error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(error)?;
        rows.into_iter()
            .filter(|(_, payload)| !is_encrypted_proxy_payload(payload))
            .collect::<Vec<_>>()
    };
    if plaintext_rows.is_empty() {
        return Ok(0);
    }

    let tx = db.transaction().map_err(error)?;
    for (subscription_id, payload) in &plaintext_rows {
        let encrypted = encrypt_proxy_payload(payload)?;
        tx.execute(
            "UPDATE proxy_payloads SET payload=?1,updated_at=CURRENT_TIMESTAMP WHERE subscription_id=?2",
            params![encrypted, subscription_id],
        )
        .map_err(error)?;
    }
    tx.commit().map_err(error)?;
    Ok(plaintext_rows.len())
}

#[cfg(debug_assertions)]
pub fn migrate_legacy_keychain_payloads_to_debug_key(db: &mut Connection) -> Result<usize, String> {
    let legacy_rows = {
        let mut statement = db
            .prepare("SELECT subscription_id,payload FROM proxy_payloads WHERE payload LIKE 'cw1:aes-256-gcm:%'")
            .map_err(error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(error)?;
        rows
    };
    if legacy_rows.is_empty() {
        return Ok(0);
    }

    let debug_key = load_or_create_key()?;
    let tx = db.transaction().map_err(error)?;
    for (subscription_id, payload) in &legacy_rows {
        let plaintext = decrypt_proxy_payload(payload)?;
        let encrypted = encrypt_proxy_payload_with_key(&plaintext, &debug_key, KEY_SOURCE_DEBUG)?;
        tx.execute(
            "UPDATE proxy_payloads SET payload=?1,updated_at=CURRENT_TIMESTAMP WHERE subscription_id=?2",
            params![encrypted, subscription_id],
        )
        .map_err(error)?;
    }
    tx.commit().map_err(error)?;
    Ok(legacy_rows.len())
}

fn load_or_create_key() -> Result<[u8; 32], String> {
    #[cfg(test)]
    {
        if let Ok(encoded) = std::env::var(TEST_KEY_ENV) {
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| "测试代理加密密钥不是有效base64")?;
            return key_from_bytes(&bytes);
        }
    }

    #[cfg(debug_assertions)]
    {
        PROXY_PAYLOAD_KEY
            .get_or_init(load_or_create_debug_key)
            .clone()
    }

    #[cfg(not(debug_assertions))]
    {
        PROXY_PAYLOAD_KEY
            .get_or_init(load_or_create_keychain_key)
            .clone()
    }
}

fn current_key_source() -> &'static str {
    #[cfg(debug_assertions)]
    {
        KEY_SOURCE_DEBUG
    }
    #[cfg(not(debug_assertions))]
    {
        KEY_SOURCE_KEYCHAIN
    }
}

fn load_key_for_source(key_source: &str) -> Result<[u8; 32], String> {
    match key_source {
        #[cfg(debug_assertions)]
        KEY_SOURCE_DEBUG => load_or_create_key(),
        KEY_SOURCE_KEYCHAIN => load_or_create_keychain_key(),
        _ => Err("代理订阅密文密钥来源无效".into()),
    }
}

#[cfg(debug_assertions)]
fn load_or_create_debug_key() -> Result<[u8; 32], String> {
    let path = debug_key_path()?;
    if path.exists() {
        let bytes =
            std::fs::read(&path).map_err(|value| format!("无法读取开发代理密钥：{value}"))?;
        return key_from_bytes(&bytes);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|value| format!("无法创建开发代理密钥目录：{value}"))?;
    }
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    write_debug_key(&path, &key)?;
    Ok(key)
}

#[cfg(debug_assertions)]
fn debug_key_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var(DEBUG_KEY_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME").map_err(|_| "无法定位用户 HOME 目录".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("CleanWeb")
        .join("dev-proxy-payload-key"))
}

#[cfg(all(debug_assertions, unix))]
fn write_debug_key(path: &std::path::Path, key: &[u8; 32]) -> Result<(), String> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|value| format!("无法创建开发代理密钥：{value}"))?;
    file.write_all(key)
        .map_err(|value| format!("无法写入开发代理密钥：{value}"))
}

#[cfg(all(debug_assertions, not(unix)))]
fn write_debug_key(path: &std::path::Path, key: &[u8; 32]) -> Result<(), String> {
    std::fs::write(path, key).map_err(|value| format!("无法写入开发代理密钥：{value}"))
}

fn load_or_create_keychain_key() -> Result<[u8; 32], String> {
    KEYCHAIN_PROXY_PAYLOAD_KEY
        .get_or_init(load_or_create_keychain_key_inner)
        .clone()
}

fn load_or_create_keychain_key_inner() -> Result<[u8; 32], String> {
    let entry = Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|value| format!("无法访问系统 Keychain：{value}"))?;
    match entry.get_secret() {
        Ok(secret) => key_from_bytes(&secret),
        Err(KeyringError::NoEntry) => {
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            entry
                .set_secret(&key)
                .map_err(|value| format!("无法保存代理加密密钥到系统 Keychain：{value}"))?;
            Ok(key)
        }
        Err(value) => Err(format!("无法读取代理加密密钥：{value}")),
    }
}

fn key_from_bytes(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "代理加密密钥长度无效".to_string())
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_payloads_without_leaking_plaintext() {
        let _guard = test_key_env_lock();
        std::env::set_var(TEST_KEY_ENV, STANDARD.encode([7_u8; 32]));
        let plaintext = "proxies:\n  - {name: a, password: secret-token}";

        let encrypted = encrypt_proxy_payload(plaintext).unwrap();

        assert!(is_encrypted_proxy_payload(&encrypted));
        assert!(!encrypted.contains("secret-token"));
        assert_eq!(decrypt_proxy_payload(&encrypted).unwrap(), plaintext);
        std::env::remove_var(TEST_KEY_ENV);
    }

    #[test]
    fn migrates_plaintext_payload_rows() {
        let _guard = test_key_env_lock();
        std::env::set_var(TEST_KEY_ENV, STANDARD.encode([8_u8; 32]));
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE proxy_payloads (
                subscription_id TEXT PRIMARY KEY,
                format TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();
        db.execute("INSERT INTO proxy_payloads(subscription_id,format,payload) VALUES('a','clash','password: secret-token')",[]).unwrap();

        assert_eq!(encrypt_existing_proxy_payloads(&mut db).unwrap(), 1);
        assert_eq!(encrypt_existing_proxy_payloads(&mut db).unwrap(), 0);

        let stored: String = db
            .query_row(
                "SELECT payload FROM proxy_payloads WHERE subscription_id='a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(is_encrypted_proxy_payload(&stored));
        assert!(!stored.contains("secret-token"));
        assert_eq!(
            decrypt_proxy_payload(&stored).unwrap(),
            "password: secret-token"
        );
        std::env::remove_var(TEST_KEY_ENV);
    }

    #[test]
    fn decrypts_multiple_payloads_with_the_same_loaded_key() {
        let _guard = test_key_env_lock();
        std::env::set_var(TEST_KEY_ENV, STANDARD.encode([9_u8; 32]));
        let first = encrypt_proxy_payload("first").unwrap();
        let second = encrypt_proxy_payload("second").unwrap();

        assert_eq!(decrypt_proxy_payload(&first).unwrap(), "first");
        assert_eq!(decrypt_proxy_payload(&second).unwrap(), "second");
        std::env::remove_var(TEST_KEY_ENV);
    }

    #[test]
    fn debug_build_can_use_a_local_key_file() {
        let _guard = test_key_env_lock();
        std::env::remove_var(TEST_KEY_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-key");
        std::env::set_var(DEBUG_KEY_PATH_ENV, &path);

        let encrypted = encrypt_proxy_payload("local-dev").unwrap();

        assert_eq!(std::fs::read(&path).unwrap().len(), 32);
        assert_eq!(decrypt_proxy_payload(&encrypted).unwrap(), "local-dev");
        std::env::remove_var(DEBUG_KEY_PATH_ENV);
    }

    #[test]
    fn debug_build_migrates_legacy_keychain_payloads_to_local_key() {
        let _guard = test_key_env_lock();
        std::env::remove_var(TEST_KEY_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-key");
        std::env::set_var(DEBUG_KEY_PATH_ENV, &path);
        let legacy_key = [3_u8; 32];
        KEYCHAIN_PROXY_PAYLOAD_KEY
            .set(Ok(legacy_key))
            .unwrap_or_else(|_| panic!("keychain test key should only be set once"));
        let legacy =
            encrypt_proxy_payload_with_key("legacy payload", &legacy_key, KEY_SOURCE_KEYCHAIN)
                .unwrap()
                .replacen(ENVELOPE_PREFIX, LEGACY_ENVELOPE_PREFIX, 1)
                .replacen(&format!("{KEY_SOURCE_KEYCHAIN}:"), "", 1);
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE proxy_payloads (
                subscription_id TEXT PRIMARY KEY,
                format TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();
        db.execute(
            "INSERT INTO proxy_payloads(subscription_id,format,payload) VALUES('legacy','clash',?1)",
            params![legacy],
        )
        .unwrap();

        assert_eq!(
            migrate_legacy_keychain_payloads_to_debug_key(&mut db).unwrap(),
            1
        );
        assert_eq!(
            migrate_legacy_keychain_payloads_to_debug_key(&mut db).unwrap(),
            0
        );

        let stored: String = db
            .query_row(
                "SELECT payload FROM proxy_payloads WHERE subscription_id='legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored.starts_with(&format!("{ENVELOPE_PREFIX}{KEY_SOURCE_DEBUG}:")));
        assert_eq!(decrypt_proxy_payload(&stored).unwrap(), "legacy payload");
        std::env::remove_var(DEBUG_KEY_PATH_ENV);
    }
}
