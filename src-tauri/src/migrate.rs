//! Bringing a vault up to format 3 after it unlocks.
//!
//! Format 3 means: every encrypted value is bound to its table, row and column
//! (see fields.rs), service and case names are encrypted too, the Argon2
//! settings are stored with the vault, and the activity log is an HMAC chain.

use std::path::Path;

use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroize;

use crate::util::fill_random;
use crate::vault::{self, KdfParams};
use crate::{activity, fields};

pub const FORMAT_3: &str = "3";

/// Columns that format 2 stored in plain text. Everything else in
/// `fields::ALL` was already encrypted, without a binding.
const PLAINTEXT_IN_FORMAT_2: &[(&str, &str)] = &[("credentials", "service"), ("projects", "name")];

pub fn schema_version(db: &Connection) -> Result<String, String> {
    db.query_row("SELECT value FROM vault_config WHERE key = 'schema_version'", [], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())
        .map(|value| value.unwrap_or_else(|| "1".into()))
}

pub fn stored_kdf_params(db: &Connection) -> Result<KdfParams, String> {
    let stored: Option<String> = db
        .query_row("SELECT value FROM vault_config WHERE key = 'kdf_params'", [], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match stored {
        Some(text) if !text.is_empty() => KdfParams::parse(&text),
        _ => Ok(KdfParams::LEGACY),
    }
}

/// Where the pre-format-3 copy lives, if this connection is file-backed.
pub fn snapshot_path(db: &Connection) -> Option<std::path::PathBuf> {
    db.path().filter(|path| !path.is_empty()).map(|path| format!("{path}.pre-v3").into())
}

/// Copy the vault to `<file>.pre-v3` once, before the first format-3
/// migration, using the same integrity-checked copy as the brand migration.
/// The format change is one-way; this file is the way back.
pub fn snapshot_before_format_3(db: &Connection) -> Result<(), String> {
    let Some(path) = db.path().filter(|path| !path.is_empty()) else {
        return Ok(()); // in-memory database (tests)
    };
    let target = format!("{path}.pre-v3");
    if Path::new(&target).exists() {
        return Ok(());
    }
    db.execute("VACUUM INTO ?1", [&target])
        .map_err(|e| format!("could not make a safety copy before upgrading the vault: {e}"))?;
    let copy = Connection::open_with_flags(&target, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("could not check the safety copy: {e}"))?;
    let integrity: String = copy.query_row("PRAGMA quick_check", [], |row| row.get(0)).map_err(|e| e.to_string())?;
    drop(copy);
    if integrity != "ok" {
        let _ = std::fs::remove_file(&target);
        return Err(format!("the safety copy failed its integrity check: {integrity}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Format 2 to 3: bind every encrypted value, encrypt names, renumber and
/// scrub the activity log. One transaction; a failure leaves format 2 intact.
///
/// A value that cannot be decrypted is left as it is and counted, rather than
/// failing the migration: one corrupt field must not lock the whole vault.
pub fn migrate_to_format_3(db: &Connection, dek: &[u8; 32]) -> Result<bool, String> {
    if schema_version(db)? != "2" {
        return Ok(false);
    }
    snapshot_before_format_3(db)?;

    crate::in_transaction(db, || {
        let mut unreadable = 0usize;
        for (table, columns) in fields::ALL {
            let select = format!("SELECT id, {} FROM {table}", columns.join(", "));
            let mut stmt = db.prepare(&select).map_err(|e| e.to_string())?;
            let rows: Vec<(String, Vec<Option<String>>)> = stmt
                .query_map([], |row| {
                    let id: String = row.get(0)?;
                    let values = (0..columns.len()).map(|i| row.get(i + 1)).collect::<Result<Vec<_>, _>>()?;
                    Ok((id, values))
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;

            for (id, values) in rows {
                for (column, stored) in columns.iter().zip(values) {
                    let Some(stored) = stored else { continue }; // NULL stays NULL
                    if stored.is_empty() || vault::is_bound(&stored) {
                        continue;
                    }
                    let plain = if PLAINTEXT_IN_FORMAT_2.contains(&(table, column)) {
                        zeroize::Zeroizing::new(stored)
                    } else {
                        match vault::decrypt(dek, &stored) {
                            Ok(plain) => plain,
                            Err(_) => {
                                unreadable += 1;
                                continue;
                            }
                        }
                    };
                    let sealed = fields::seal(dek, table, &id, column, &plain)?;
                    db.execute(&format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2"), rusqlite::params![sealed, id])
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        // The log used to record login names in plain text ("added GitHub").
        let scrubbed = db
            .execute(
                "UPDATE activity_log SET detail = 'added a login' WHERE action = 'credential_add' AND detail != 'added a login'",
                [],
            )
            .map_err(|e| e.to_string())?;
        activity::renumber(db)?;

        let mut detail = format!("vault format 3; login names removed from {scrubbed} older log entries");
        if unreadable > 0 {
            detail.push_str(&format!("; {unreadable} unreadable values left unchanged"));
        }
        activity::log_action(db, "migration", &detail);
        db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', ?1)", [FORMAT_3])
            .map_err(|e| e.to_string())?;
        Ok(())
    })?;
    Ok(true)
}

/// Re-wrap the data key with the current Argon2 settings if the vault still
/// uses weaker ones. Needs the master password, so it runs at unlock.
pub fn upgrade_kdf(db: &Connection, master_password: &str, dek: &[u8; 32]) -> Result<bool, String> {
    if !stored_kdf_params(db)?.weaker_than(&KdfParams::CURRENT) {
        return Ok(false);
    }
    let mut salt = [0u8; 32];
    fill_random(&mut salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let mut wrapping_key = vault::derive_key_with(master_password, &salt, KdfParams::CURRENT)?;
    let wrapped = vault::wrap_dek(dek, &wrapping_key);
    wrapping_key.zeroize();
    let wrapped = wrapped?;
    let pass_hash = vault::hash_password_with(master_password, KdfParams::CURRENT)?;
    let params = KdfParams::CURRENT.encode();

    crate::in_transaction(db, || {
        for (key, value) in [
            ("encrypted_dek", wrapped.as_str()),
            ("password_hash", pass_hash.as_str()),
            ("kdf_salt", salt_b64.as_str()),
            ("kdf_params", params.as_str()),
        ] {
            db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES (?1, ?2)", rusqlite::params![key, value])
                .map_err(|e| e.to_string())?;
        }
        activity::log_action(db, "kdf_upgrade", &format!("key derivation strengthened to {params}"));
        Ok(())
    })?;
    Ok(true)
}
