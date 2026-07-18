use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyring::{Entry, Error as KeyringError};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
use std::sync::{Mutex, OnceLock};

const ENVELOPE_PREFIX: &str = "cw1:aes-256-gcm:";
const KEYCHAIN_SERVICE: &str = "CleanWeb";
const KEYCHAIN_ACCOUNT: &str = "proxy-payload-key";
#[cfg(test)]
const TEST_KEY_ENV: &str = "CLEANWEB_TEST_PROXY_KEY_B64";

#[cfg(test)]
pub(crate) fn test_key_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

pub fn encrypt_proxy_payload(plaintext: &str) -> Result<String, String> {
    let key = load_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "代理加密密钥无效")?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| "代理加密 nonce 无效")?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "代理订阅加密失败")?;
    Ok(format!(
        "{ENVELOPE_PREFIX}{}:{}",
        STANDARD.encode(nonce_bytes),
        STANDARD.encode(ciphertext)
    ))
}

pub fn decrypt_proxy_payload(envelope: &str) -> Result<String, String> {
    if !is_encrypted_proxy_payload(envelope) {
        return Err("代理订阅载荷不是 CleanWeb 密文".into());
    }
    let key = load_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "代理加密密钥无效")?;
    let body = envelope
        .strip_prefix(ENVELOPE_PREFIX)
        .ok_or_else(|| "代理订阅密文格式无效".to_string())?;
    let (nonce, ciphertext) = body
        .split_once(':')
        .ok_or_else(|| "代理订阅密文格式无效".to_string())?;
    let nonce = STANDARD
        .decode(nonce)
        .map_err(|_| "代理订阅密文 nonce 无效")?;
    if nonce.len() != 12 {
        return Err("代理订阅密文 nonce 长度无效".into());
    }
    let ciphertext = STANDARD
        .decode(ciphertext)
        .map_err(|_| "代理订阅密文内容无效")?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| "代理订阅密文 nonce 无效")?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| "代理订阅解密失败")?;
    String::from_utf8(plaintext).map_err(|_| "代理订阅明文不是有效UTF-8文本".into())
}

pub fn is_encrypted_proxy_payload(value: &str) -> bool {
    value.starts_with(ENVELOPE_PREFIX)
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

    static KEY_CACHE: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();
    cached_key(
        KEY_CACHE.get_or_init(|| Mutex::new(None)),
        read_or_create_keychain_key,
    )
}

fn cached_key(
    cache: &Mutex<Option<[u8; 32]>>,
    loader: impl FnOnce() -> Result<[u8; 32], String>,
) -> Result<[u8; 32], String> {
    let mut cached = cache.lock().map_err(|_| "代理加密密钥缓存不可用")?;
    if let Some(key) = *cached {
        return Ok(key);
    }
    let key = loader()?;
    *cached = Some(key);
    Ok(key)
}

fn read_or_create_keychain_key() -> Result<[u8; 32], String> {
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
    fn keychain_loader_runs_only_once_per_process_cache() {
        let cache = Mutex::new(None);
        let calls = std::sync::atomic::AtomicUsize::new(0);

        let first = cached_key(&cache, || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok([9_u8; 32])
        })
        .unwrap();
        let second = cached_key(&cache, || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok([3_u8; 32])
        })
        .unwrap();

        assert_eq!(first, [9_u8; 32]);
        assert_eq!(second, first);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
