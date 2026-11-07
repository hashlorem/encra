//! Credential reads that keep secrets in Rust.
//!
//! The webview gets list metadata and asks for one field of one login at a
//! time. Nothing here returns every password at once, which is what the old
//! `get_credentials` did on every unlock.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{totp, vault};

/// What the vault list shows. No password, notes or 2FA secret.
#[derive(Debug, Serialize, PartialEq)]
pub struct CredentialSummary {
    pub id: String,
    pub service: String,
    pub username: String,
    pub has_totp: bool,
    pub created_at: String,
}

/// The open record, minus the password and 2FA secret.
#[derive(Debug, Serialize, PartialEq)]
pub struct CredentialDetail {
    pub id: String,
    pub service: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub has_totp: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
}

/// What the record page says about a password, without the password itself.
#[derive(Debug, Serialize, PartialEq)]
pub struct PasswordProfile {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

/// A field the user can copy from a login.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CopyField {
    Username,
    Password,
    Url,
    Totp,
}

const NOT_FOUND: &str = "credential not found";
const UNREADABLE: &str = "could not decrypt that field";

/// Decrypt an optional display field. A blank or unreadable value shows as
/// empty rather than failing the whole list.
fn display_field(key: &[u8; 32], stored: String) -> String {
    vault::decrypt_opt(key, &Some(stored)).unwrap_or_default()
}

pub fn list_summaries(db: &Connection, key: &[u8; 32]) -> Result<Vec<CredentialSummary>, String> {
    let mut stmt = db
        .prepare("SELECT id, service, username, totp_secret IS NOT NULL, created_at FROM credentials ORDER BY service COLLATE NOCASE")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|(id, service, username, has_totp, created_at)| CredentialSummary {
            id,
            service,
            username: display_field(key, username),
            has_totp,
            created_at,
        })
        .collect())
}

pub fn detail(db: &Connection, key: &[u8; 32], id: &str) -> Result<CredentialDetail, String> {
    let row = db
        .query_row(
            "SELECT id, service, username, url, notes, totp_secret IS NOT NULL, created_at FROM credentials WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    row.get::<_, bool>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or(NOT_FOUND)?;

    let (id, service, username, url, notes, has_totp, created_at) = row;
    Ok(CredentialDetail {
        id,
        service,
        username: display_field(key, username),
        url: display_field(key, url),
        notes: display_field(key, notes),
        has_totp,
        created_at,
    })
}

fn stored_column(db: &Connection, id: &str, column: &str) -> Result<Option<String>, String> {
    // `column` is one of a fixed set chosen below, never user input.
    db.query_row(&format!("SELECT {column} FROM credentials WHERE id = ?1"), [id], |row| row.get::<_, Option<String>>(0))
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| NOT_FOUND.to_string())
}

/// Decrypt one stored column. Unlike the list, a failure here is an error:
/// the old code returned the literal text "[decryption failed]" as if it were
/// the password, which could then be copied and pasted somewhere.
fn decrypt_column(db: &Connection, key: &[u8; 32], id: &str, column: &str) -> Result<Zeroizing<String>, String> {
    match stored_column(db, id, column)? {
        Some(value) if !value.is_empty() => vault::decrypt(key, &value).map_err(|_| UNREADABLE.into()),
        _ => Ok(Zeroizing::new(String::new())),
    }
}

pub fn reveal_password(db: &Connection, key: &[u8; 32], id: &str) -> Result<Zeroizing<String>, String> {
    decrypt_column(db, key, id, "password_encrypted")
}

pub fn totp_code(db: &Connection, key: &[u8; 32], id: &str) -> Result<Option<TotpCode>, String> {
    let secret = decrypt_column(db, key, id, "totp_secret")?;
    if secret.is_empty() {
        return Ok(None);
    }
    Ok(Some(TotpCode { code: totp::generate_code(&secret)?, remaining: totp::remaining_seconds() }))
}

/// The plaintext for a copy. Empty values are refused so a copy never
/// silently clears the clipboard.
pub fn copy_value(db: &Connection, key: &[u8; 32], id: &str, field: CopyField) -> Result<Zeroizing<String>, String> {
    let value = match field {
        CopyField::Username => decrypt_column(db, key, id, "username")?,
        CopyField::Password => reveal_password(db, key, id)?,
        CopyField::Url => decrypt_column(db, key, id, "url")?,
        CopyField::Totp => match totp_code(db, key, id)? {
            Some(code) => Zeroizing::new(code.code),
            None => return Err("no 2FA set up for this login".into()),
        },
    };
    if value.is_empty() {
        return Err("that field is empty".into());
    }
    Ok(value)
}

pub fn describe_password(db: &Connection, key: &[u8; 32], id: &str) -> Result<PasswordProfile, String> {
    let password = reveal_password(db, key, id)?;
    Ok(PasswordProfile {
        length: password.chars().count(),
        lowercase: password.chars().any(|c| c.is_lowercase()),
        uppercase: password.chars().any(|c| c.is_uppercase()),
        digits: password.chars().any(|c| c.is_ascii_digit()),
        symbols: password.chars().any(|c| !c.is_alphanumeric()),
    })
}
