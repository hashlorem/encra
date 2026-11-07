use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine;
use rand::RngCore;
use rusqlite::Connection;
use serde::Deserialize;
use std::ops::Deref;
use std::path::Path;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::util::os_rng;

/// A live Data Encryption Key held in memory for the duration of a command.
///
/// The buffer is overwritten when this value is dropped, so a copy handed out by
/// `require_unlocked` does not linger on the stack after the command finishes.
/// This is best-effort only: it cannot defend against swap, core dumps, or an
/// attacker who already controls the machine.
pub struct Dek([u8; 32]);

impl Dek {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Deref for Dek {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// --- Models ---

#[derive(Debug, Deserialize)]
pub struct CredentialInput {
    pub service: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

// --- App state ---

pub struct AppState {
    pub db: Mutex<Connection>,
    /// The unlocked data key. `Dek` wipes itself on drop, so clearing or
    /// replacing it never leaves the old bytes behind.
    pub encryption_key: Mutex<Option<Dek>>,
}

// --- DB setup ---

pub fn init_db(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            url TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            totp_secret TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vault_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- encrypted_dek: the AES-GCM encrypted data encryption key, wrapped by the master-password-derived wrapping key
        -- password_hash: Argon2id hash of the master password (for verification only)
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('encrypted_dek', '');
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('password_hash', '');
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('schema_version', '1');
        ",
    )
    .map_err(|e| e.to_string())?;

    // Migration: add totp_secret column if upgrading from older schema
    conn.execute("ALTER TABLE credentials ADD COLUMN totp_secret TEXT", [])
        .ok();

    Ok(conn)
}

// --- Crypto ---

/// Argon2id cost settings. Stored with the vault (and in each backup) so they
/// can be raised later without guessing what an existing vault used.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// What every vault used before format 3: the argon2 crate's defaults.
    pub const LEGACY: Self = Self { m: 19_456, t: 2, p: 1 };
    /// 256 MiB, 3 passes: about 320 ms per derivation on an Apple M5.
    pub const CURRENT: Self = Self { m: 262_144, t: 3, p: 1 };
    /// Upper bounds for settings read from a file, which may be hostile: a
    /// backup claiming 64 GiB of memory must not be able to exhaust RAM.
    const MAX_M: u32 = 1_048_576;
    const MAX_T: u32 = 10;
    const MAX_P: u32 = 4;

    pub fn encode(&self) -> String {
        format!("m={},t={},p={}", self.m, self.t, self.p)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut params = Self { m: 0, t: 0, p: 0 };
        for part in text.split(',') {
            let (name, value) = part.split_once('=').ok_or("invalid key-derivation settings")?;
            let value: u32 = value.parse().map_err(|_| "invalid key-derivation settings")?;
            match name {
                "m" => params.m = value,
                "t" => params.t = value,
                "p" => params.p = value,
                _ => return Err("invalid key-derivation settings".into()),
            }
        }
        let within = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if !within(params.m, 8 * params.p.max(1), Self::MAX_M) || !within(params.t, 1, Self::MAX_T) || !within(params.p, 1, Self::MAX_P) {
            return Err("key-derivation settings are out of range".into());
        }
        Ok(params)
    }

    /// Whether these settings are cheaper to attack than `target`.
    pub fn weaker_than(&self, target: &Self) -> bool {
        self.m < target.m || self.t < target.t
    }

    fn argon2(&self) -> Result<Argon2<'static>, String> {
        let params = argon2::Params::new(self.m, self.t, self.p, Some(32)).map_err(|e| e.to_string())?;
        Ok(Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params))
    }
}

/// Derive a 32-byte wrapping key from a password with the given settings.
pub fn derive_key_with(password: &str, salt: &[u8], params: KdfParams) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    params
        .argon2()?
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// Derive with the pre-format-3 settings. Only for reading what older vaults
/// and backups wrote.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    derive_key_with(password, salt, KdfParams::LEGACY)
}

/// Generate a fresh random 32-byte Data Encryption Key
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    os_rng().fill_bytes(&mut dek);
    dek
}

/// Wrap (encrypt) the DEK with a wrapping key
pub fn wrap_dek(dek: &[u8; 32], wrapping_key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    os_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, dek.as_ref())
        .map_err(|e| e.to_string())?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Unwrap (decrypt) the DEK using a wrapping key
pub fn unwrap_dek(encrypted: &str, wrapping_key: &[u8; 32]) -> Result<[u8; 32], String> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| e.to_string())?;

    if combined.len() < 12 {
        return Err("invalid wrapped DEK".into());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|e| e.to_string())?;

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "failed to unwrap DEK — wrong password".to_string())?;

    // A valid AES-GCM tag proves integrity but not the payload shape. A corrupted
    // or tampered vault can decrypt to the wrong length, so check before copying
    // rather than panicking on a malformed key.
    if plaintext.len() != 32 {
        return Err(format!(
            "corrupted DEK: expected 32 bytes, got {}",
            plaintext.len()
        ));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(dek)
}

/// Encrypt plaintext with the DEK
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;

    let mut nonce_bytes = [0u8; 12];
    os_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt ciphertext with the DEK. The plaintext, and every intermediate
/// buffer, is wiped when dropped.
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Zeroizing<String>, String> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| e.to_string())?;

    if combined.len() < 12 {
        return Err("invalid encrypted data".into());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "decryption failed — wrong key or corrupted data".to_string())?,
    );
    let text = std::str::from_utf8(&plaintext).map_err(|_| "decrypted data is not valid text".to_string())?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Decrypt a value that is about to leave Rust (for the webview or a
/// backup). The returned copy is plain by necessity; the intermediates are not.
pub fn decrypt_to_string(key: &[u8; 32], encoded: &str) -> Result<String, String> {
    decrypt(key, encoded).map(|text| text.as_str().to_owned())
}

/// Hash a password for verification ONLY — Argon2 PHC format, non-reversible.
/// The PHC string records its own settings, so verification needs no extra
/// state.
pub fn hash_password_with(password: &str, params: KdfParams) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let mut rng = os_rng();
    let salt = SaltString::generate(&mut rng);
    let hash = params
        .argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    Ok(hash.to_string())
}

pub fn hash_password(password: &str) -> Result<String, String> {
    hash_password_with(password, KdfParams::CURRENT)
}

// --- Field encryption bound to its place (vault format 3) ---

/// Marks a value encrypted with associated data. Values without it are the
/// format-2 unbound kind, which only the migration reads.
const BOUND_PREFIX: &str = "v2:";

/// Encrypt with AES-256-GCM, authenticating `aad` alongside the ciphertext.
/// A value moved to another row or field no longer decrypts.
pub fn encrypt_bound(key: &[u8; 32], plaintext: &str, aad: &str) -> Result<String, String> {
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    os_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: plaintext.as_bytes(), aad: aad.as_bytes() })
        .map_err(|e| e.to_string())?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(format!("{BOUND_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(&combined)))
}

/// Decrypt a bound value. Unbound (format 2) values are refused: accepting
/// them would let anyone holding an older copy of the file paste an old value
/// into a new row. An empty stored value is an empty field.
pub fn decrypt_bound(key: &[u8; 32], stored: &str, aad: &str) -> Result<Zeroizing<String>, String> {
    use aes_gcm::aead::Payload;
    if stored.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    let encoded = stored.strip_prefix(BOUND_PREFIX).ok_or("value is not in the current vault format")?;
    let combined = base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|e| e.to_string())?;
    if combined.len() < 12 {
        return Err("invalid encrypted data".into());
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ciphertext, aad: aad.as_bytes() })
            .map_err(|_| "decryption failed — wrong key, corrupted data, or a value moved from elsewhere".to_string())?,
    );
    let text = std::str::from_utf8(&plaintext).map_err(|_| "decrypted data is not valid text".to_string())?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn is_bound(stored: &str) -> bool {
    stored.starts_with(BOUND_PREFIX)
}

/// Verify a password against a PHC-format hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    use argon2::password_hash::PasswordVerifier;
    let parsed = argon2::PasswordHash::new(hash).map_err(|e| e.to_string())?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

