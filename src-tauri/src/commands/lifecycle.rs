//! Creating, unlocking and sealing the vault, and bringing old vaults up to date.

use std::sync::Arc;
use base64::Engine;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::clipboard::ClipboardGuard;
use crate::db::*;
use crate::util::{constant_time_eq, fill_random, wipe_strings};
use crate::vault::{self, AppState, Dek};
use crate::{activity, agent, migrate};

/// Every migration a vault may need once its data key is known, in order:
/// format 1 to 2 (encrypt plain fields), 2 to 3 (bind every value, encrypt
/// names), stronger Argon2 settings, then sealing the activity log. Shared by
/// unlock, legacy unlock and recovery, so no path opens an unmigrated vault.
pub(crate) fn bring_up_to_date(db: &Connection, master_password: &str, dek: &[u8; 32]) -> Result<(), String> {
    migrate_plaintext_fields(db, dek)?;
    migrate::migrate_to_format_3(db, dek)?;
    migrate::upgrade_kdf(db, master_password, dek)?;
    seal_log(db, dek);
    Ok(())
}



/// What the vault file holds, read before anything is decrypted.
#[derive(Debug, PartialEq)]
pub(crate) enum VaultKind {
    /// No master password has been set yet.
    Fresh,
    /// A pre-DEK vault that migrates on its first unlock.
    Legacy(String),
    /// A DEK-model vault.
    Current { encrypted_dek: String, password_hash: String },
}

pub(crate) fn vault_kind(db: &Connection) -> Result<VaultKind, String> {
    let read = |key: &str| -> Result<String, String> {
        db.query_row("SELECT COALESCE((SELECT value FROM vault_config WHERE key = ?1), '')", [key], |row| row.get(0))
            .map_err(|e| e.to_string())
    };
    let encrypted_dek = read("encrypted_dek")?;
    let password_hash = read("password_hash")?;
    let legacy_hash = read("master_hash")?;
    Ok(match (encrypted_dek.is_empty() && password_hash.is_empty(), legacy_hash.is_empty()) {
        (true, true) => VaultKind::Fresh,
        (true, false) => VaultKind::Legacy(legacy_hash),
        (false, _) => VaultKind::Current { encrypted_dek, password_hash },
    })
}

/// Set the master password on a fresh vault and return its new data key.
///
/// Refuses if a vault already exists, so creating can never overwrite one.
/// Everything is written in one transaction: a failure leaves the vault fresh.
pub(crate) fn create_vault_impl(db: &Connection, master_password: &str) -> Result<[u8; 32], String> {
    if vault_kind(db)? != VaultKind::Fresh {
        return Err("a vault already exists".into());
    }
    // The one path where the password is chosen, so the one place a strength
    // rule can be enforced without locking anyone out of an older vault.
    require_min_length(master_password, "Master password", MIN_MASTER_PASSWORD_CHARS)?;

    let mut kdf_salt = [0u8; 32];
    fill_random(&mut kdf_salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(kdf_salt);
    let params = vault::KdfParams::CURRENT.encode();
    let mut wrapping_key = vault::derive_key_with(master_password, &kdf_salt, vault::KdfParams::CURRENT)?;
    let dek = vault::generate_dek();
    let wrapped = vault::wrap_dek(&dek, &wrapping_key);
    wrapping_key.zeroize();
    let wrapped = wrapped?;
    let pass_hash = vault::hash_password(master_password)?;

    in_transaction(db, || {
        for (key, value) in [
            ("encrypted_dek", wrapped.as_str()),
            ("password_hash", pass_hash.as_str()),
            ("kdf_salt", salt_b64.as_str()),
            ("kdf_params", params.as_str()),
            ("schema_version", migrate::FORMAT_3),
        ] {
            db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES (?1, ?2)", rusqlite::params![key, value])
                .map_err(|e| e.to_string())?;
        }
        activity::log_action(db, "vault_created", "new vault created");
        Ok(())
    })?;
    seal_log(db, &dek);
    Ok(dek)
}

/// Unlock a DEK-model vault. `Ok(None)` means a wrong password, which is
/// recorded in the activity log.
pub(crate) fn unlock_current_vault(db: &Connection, master_password: &str) -> Result<Option<[u8; 32]>, String> {
    let VaultKind::Current { encrypted_dek, password_hash } = vault_kind(db)? else {
        return Err("no unlockable vault".into());
    };

    if !vault::verify_password(master_password, &password_hash)? {
        activity::log_action(db, "unlock_failed", "wrong master password");
        return Ok(None);
    }

    let stored_salt: String = db.query_row("SELECT COALESCE((SELECT value FROM vault_config WHERE key = 'kdf_salt'), '')", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if stored_salt.is_empty() {
        return Err("vault has no key-derivation salt".into());
    }
    let kdf_salt = base64::engine::general_purpose::STANDARD.decode(&stored_salt).map_err(|e| e.to_string())?;

    let params = migrate::stored_kdf_params(db)?;
    let mut wrapping_key = vault::derive_key_with(master_password, &kdf_salt, params)?;
    let dek = vault::unwrap_dek(&encrypted_dek, &wrapping_key);
    wrapping_key.zeroize();
    let dek = dek?;

    // Migrate before publishing the key, so a failed migration leaves the vault
    // locked rather than unlocked in a half-migrated state.
    bring_up_to_date(db, master_password, &dek)?;
    activity::log_action(db, "unlock", "vault unlocked");
    seal_log(db, &dek);
    Ok(Some(dek))
}

/// Whether a master password exists yet, so the first launch shows setup
/// instead of an unlock form. It says nothing the database file's own
/// presence doesn't, and it decrypts nothing.
/// Whether the pre-format-3 safety copy is still on disk. It holds the vault
/// with the older, weaker protection, so Settings offers to delete it.
#[tauri::command]
pub(crate) fn safety_copy_exists(state: tauri::State<AppState>) -> Result<bool, String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    Ok(migrate::snapshot_path(&db).is_some_and(|path| path.exists()))
}

#[tauri::command]
pub(crate) fn delete_safety_copy(state: tauri::State<AppState>) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let Some(path) = migrate::snapshot_path(&db) else { return Ok(()) };
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("could not delete the safety copy: {e}"))?;
        activity::log_action(&db, "safety_copy_deleted", "pre-upgrade safety copy deleted");
        seal_log(&db, &key);
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn vault_status(state: tauri::State<AppState>) -> Result<&'static str, String> {
    let db = require_db(&state)?;
    Ok(if vault_kind(&db)? == VaultKind::Fresh { "new" } else { "sealed" })
}

#[tauri::command]
pub(crate) fn create_vault(state: tauri::State<AppState>, master_password: String) -> Result<(), String> {
    let db = require_db(&state)?;
    let mut dek = create_vault_impl(&db, &master_password)?;
    let mut key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    *key = Some(Dek::new(dek));
    dek.zeroize();
    Ok(())
}

#[tauri::command]
pub(crate) fn unlock_vault(state: tauri::State<AppState>, master_password: String) -> Result<bool, String> {
    let db = require_db(&state)?;
    match vault_kind(&db)? {
        // Unlocking no longer creates a vault; that is create_vault's job, behind
        // a confirmed password on the setup screen.
        VaultKind::Fresh => Err("no vault has been created yet".into()),
        VaultKind::Legacy(legacy_hash) => migrate_legacy_vault(&db, &state, &master_password, &legacy_hash),
        VaultKind::Current { .. } => match unlock_current_vault(&db, &master_password)? {
            Some(mut dek) => {
                let mut key = state.encryption_key.lock().map_err(|e| e.to_string())?;
                *key = Some(Dek::new(dek));
                dek.zeroize();
                Ok(true)
            }
            None => Ok(false),
        },
    }
}

/// Migrate a legacy vault (pre-DEK model) to the new DEK model.
/// Legacy vaults have master_hash = base64(derive_key(password, legacy_salt)).
/// We decrypt all credentials with that legacy key, re-encrypt under a new random DEK,
/// wrap the DEK, and replace master_hash with password_hash.
pub(crate) fn migrate_legacy_vault(
    db: &Connection,
    state: &AppState,
    master_password: &str,
    legacy_hash: &str,
) -> Result<bool, String> {
    // Legacy salt: the original hardcoded salt from the pre-DEK era
    let legacy_salt = [0x4b, 0x65, 0x79, 0x52, 0x50, 0x54, 0x30, 0x31]; // "KeyRPT01"

    // Derive the legacy key and verify
    let mut legacy_key = vault::derive_key(master_password, &legacy_salt)?;
    let check_hash = base64::engine::general_purpose::STANDARD.encode(legacy_key);
    // Constant-time: this comparison decides whether the caller guessed the
    // master password, so it must not leak how many leading bytes matched.
    if !constant_time_eq(check_hash.as_bytes(), legacy_hash.as_bytes()) {
        legacy_key.zeroize();
        activity::log_action(db, "unlock_failed", "wrong master password");
        return Ok(false);
    }

    // Read all existing credentials (encrypted with legacy key)
    let mut stmt = db
        .prepare("SELECT id, service, username, password_encrypted, url, notes, totp_secret, created_at FROM credentials")
        .map_err(|e| e.to_string())?;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct RawCred {
        id: String, service: String, username: String,
        password_encrypted: String, url: String,
        notes: String, totp_secret: Option<String>, created_at: String,
    }

    let raw_creds: Vec<RawCred> = stmt
        .query_map([], |row| Ok(RawCred {
            id: row.get(0)?, service: row.get(1)?, username: row.get(2)?,
            password_encrypted: row.get(3)?, url: row.get(4)?,
            notes: row.get(5)?, totp_secret: row.get(6)?, created_at: row.get(7)?,
        }))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    // Decrypt passwords with legacy key
    let mut decrypted_passwords: Vec<String> = Vec::new();
    for cred in &raw_creds {
        let plain = vault::decrypt_to_string(&legacy_key, &cred.password_encrypted)?;
        decrypted_passwords.push(plain);
    }

    // Generate new DEK + new per-vault salt + wrapping key
    let new_dek = vault::generate_dek();
    let mut new_salt = [0u8; 32];
    fill_random(&mut new_salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(new_salt);
    let mut wrapping_key = vault::derive_key(master_password, &new_salt)?;
    let wrapped_dek = vault::wrap_dek(&new_dek, &wrapping_key)?;
    wrapping_key.zeroize();
    let pass_hash = vault::hash_password(master_password)?;

    // Run entire migration in a transaction
    in_transaction(db, || {
        // Re-encrypt all credentials with new DEK
        for (i, cred) in raw_creds.iter().enumerate() {
            let new_enc = vault::encrypt(&new_dek, &decrypted_passwords[i])?;
            db.execute(
                "UPDATE credentials SET password_encrypted = ?1 WHERE id = ?2",
                rusqlite::params![new_enc, cred.id],
            ).map_err(|e| e.to_string())?;
        }

        // Write new vault config
        db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped_dek]).map_err(|e| e.to_string())?;
        db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).map_err(|e| e.to_string())?;
        db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).map_err(|e| e.to_string())?;

        // Clear legacy master_hash
        db.execute("DELETE FROM vault_config WHERE key = 'master_hash'", []).map_err(|e| e.to_string())?;
        Ok(())
    })
    .map_err(|e| format!("migration failed: {}", e))?;

    legacy_key.zeroize();
    wipe_strings(&mut decrypted_passwords);

    activity::log_action(db, "migration", "legacy vault migrated to DEK model");
    bring_up_to_date(db, master_password, &new_dek)?;

    {
        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(Dek::new(new_dek));
    }
    Ok(true)
}

/// Migrate plaintext fields to encrypted (schema v1 → v2).
pub(crate) fn migrate_plaintext_fields(db: &Connection, dek: &[u8; 32]) -> Result<(), String> {
    let version: String = db.query_row(
        "SELECT value FROM vault_config WHERE key = 'schema_version'",
        [], |r| r.get(0)
    ).unwrap_or_else(|_| "1".into());

    if version != "1" { return Ok(()); }

    // All five tables plus the version bump commit together. Previously a
    // failure part-way through left some fields encrypted and others plaintext
    // while the version still advertised v1, so the next unlock would re-encrypt
    // the fields that had already succeeded.
    in_transaction(db, || migrate_plaintext_fields_inner(db, dek))
}

/// The table-by-table migration body. Always runs inside a transaction.
pub(crate) fn migrate_plaintext_fields_inner(db: &Connection, dek: &[u8; 32]) -> Result<(), String> {
    // credentials: username, url, notes
    {
        let mut stmt = db.prepare("SELECT id, username, url, notes FROM credentials").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        for (id, u, url, n) in rows {
            db.execute("UPDATE credentials SET username=?1, url=?2, notes=?3 WHERE id=?4",
                rusqlite::params![vault::encrypt(dek, &u)?, vault::encrypt(dek, &url)?, vault::encrypt(dek, &n)?, id]).map_err(|e| e.to_string())?;
        }
    }
    // TOTP secrets
    {
        let mut stmt = db.prepare("SELECT id, totp_secret FROM credentials WHERE totp_secret IS NOT NULL AND totp_secret != ''").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        for (id, sec) in rows {
            db.execute("UPDATE credentials SET totp_secret=?1 WHERE id=?2",
                rusqlite::params![vault::encrypt(dek, &sec)?, id]).map_err(|e| e.to_string())?;
        }
    }
    // projects: description, target, methodology
    {
        let mut stmt = db.prepare("SELECT id, description, target, methodology FROM projects").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        for (id, d, t, m) in rows {
            db.execute("UPDATE projects SET description=?1, target=?2, methodology=?3 WHERE id=?4",
                rusqlite::params![vault::encrypt(dek, &d)?, vault::encrypt(dek, &t)?, vault::encrypt(dek, &m)?, id]).map_err(|e| e.to_string())?;
        }
    }
    // journal_entries: title, content
    {
        let mut stmt = db.prepare("SELECT id, title, content FROM journal_entries").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        for (id, t, c) in rows {
            db.execute("UPDATE journal_entries SET title=?1, content=?2 WHERE id=?3",
                rusqlite::params![vault::encrypt(dek, &t)?, vault::encrypt(dek, &c)?, id]).map_err(|e| e.to_string())?;
        }
    }
    // kb_entries: title, command, description, tags
    {
        let mut stmt = db.prepare("SELECT id, title, command, description, tags FROM kb_entries").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String, String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        for (id, ti, cmd, d, ta) in rows {
            db.execute("UPDATE kb_entries SET title=?1, command=?2, description=?3, tags=?4 WHERE id=?5",
                rusqlite::params![vault::encrypt(dek, &ti)?, vault::encrypt(dek, &cmd)?, vault::encrypt(dek, &d)?, vault::encrypt(dek, &ta)?, id]).map_err(|e| e.to_string())?;
        }
    }

    db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).map_err(|e| e.to_string())?;
    Ok(())
}

/// How the vault was sealed, for the log. The webview sends one of a fixed set
/// of codes and the wording comes from here, so it can't write free text into
/// the log.
pub(crate) fn seal_detail(reason: Option<&str>) -> &'static str {
    match reason {
        Some("button") => "sealed with the Seal button",
        Some("shortcut") => "sealed with the keyboard shortcut",
        Some("idle") => "sealed after 5 idle minutes",
        Some("app_switch") => "sealed when Encra lost focus",
        _ => "vault locked",
    }
}

#[tauri::command]
pub(crate) fn lock_vault(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    hub: tauri::State<Arc<agent::server::Hub>>,
    reason: Option<String>,
) -> Result<(), String> {
    // Every lock path (button, shortcut, idle timer, blur) ends here, so this
    // is the one place a still-pending copied secret gets wiped.
    clipboard.wipe_now();
    // Nothing waiting for approval may outlive the seal.
    hub.cancel_all("the vault was sealed");
    let db = require_db(&state)?;
    activity::log_action(&db, "lock", seal_detail(reason.as_deref()));
    let mut key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    if let Some(dek) = key.as_ref() {
        seal_log(&db, dek);
    }
    // Dropping the Dek overwrites the key bytes in place.
    *key = None;
    Ok(())
}
