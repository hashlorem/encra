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

/// Derive a 32-byte wrapping key from a password using Argon2id
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
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

/// Hash a password for verification ONLY — uses Argon2 PHC format, non-reversible
pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let mut rng = os_rng();
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    Ok(hash.to_string())
}

/// Verify a password against a PHC-format hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    use argon2::password_hash::PasswordVerifier;
    let parsed = argon2::PasswordHash::new(hash).map_err(|e| e.to_string())?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// --- Field-level encryption helpers ---

/// Decrypt an optional string field with the DEK. None → None, decryption failure → None.
pub fn decrypt_opt(key: &[u8; 32], value: &Option<String>) -> Option<String> {
    match value {
        Some(v) if !v.is_empty() => decrypt_to_string(key, v).ok(),
        _ => None,
    }
}
