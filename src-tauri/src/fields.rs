//! Where each encrypted value lives, and the associated data that binds it
//! there (vault format 3).
//!
//! Every encrypted column is sealed with "encra:v1:<table>:<id>:<column>" as
//! AES-GCM associated data, so a value copied into another row or column fails
//! to decrypt instead of showing up somewhere it does not belong.

use zeroize::Zeroizing;

use crate::vault;

pub const CREDENTIAL_FIELDS: &[&str] = &["service", "username", "password_encrypted", "url", "notes", "totp_secret", "breach_result"];
pub const PROJECT_FIELDS: &[&str] = &["name", "description", "target", "methodology"];
pub const ENTRY_FIELDS: &[&str] = &["title", "content"];
pub const KB_FIELDS: &[&str] = &["title", "command", "description", "tags"];

/// The encrypted columns of every table, for migrations and checks.
pub const ALL: &[(&str, &[&str])] = &[
    ("credentials", CREDENTIAL_FIELDS),
    ("projects", PROJECT_FIELDS),
    ("journal_entries", ENTRY_FIELDS),
    ("kb_entries", KB_FIELDS),
];

pub fn aad(table: &str, id: &str, column: &str) -> String {
    format!("encra:v1:{table}:{id}:{column}")
}

pub fn seal(key: &[u8; 32], table: &str, id: &str, column: &str, plaintext: &str) -> Result<String, String> {
    vault::encrypt_bound(key, plaintext, &aad(table, id, column))
}

pub fn open(key: &[u8; 32], table: &str, id: &str, column: &str, stored: &str) -> Result<Zeroizing<String>, String> {
    vault::decrypt_bound(key, stored, &aad(table, id, column))
}

/// For values about to leave Rust (the webview, a backup).
pub fn open_to_string(key: &[u8; 32], table: &str, id: &str, column: &str, stored: &str) -> Result<String, String> {
    open(key, table, id, column, stored).map(|text| text.as_str().to_owned())
}
