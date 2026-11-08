//! Shared guards for commands: the vault must be unlocked, writes are
//! all-or-nothing, and field and password limits.

use rusqlite::Connection;

use crate::vault::{AppState, Dek};
use crate::activity;

/// Minimum master-password length accepted when a password is *created* or
/// *changed*. It is deliberately not enforced when verifying an existing
/// password, so a vault created before this rule can still be unlocked.
pub(crate) const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Minimum length for a backup password, which protects the entire vault.
pub(crate) const MIN_BACKUP_PASSWORD_CHARS: usize = 8;

pub(crate) const MAX_FIELD_CHARS: usize = 8_192;
pub(crate) const MAX_LONG_FIELD_CHARS: usize = 65_536;

/// Check vault is unlocked — returns the DEK in a guard that wipes it on drop.
pub(crate) fn require_unlocked(state: &AppState) -> Result<Dek, String> {
    let key = state.encryption_key.lock().map_err(|e| e.to_string())?;
    key.as_ref().map(|dek| Dek::new(**dek)).ok_or_else(|| "vault is locked".into())
}

pub(crate) fn require_db(state: &AppState) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
    state.db.lock().map_err(|e| e.to_string())
}

/// Run `write` inside one immediate transaction, rolling back on any failure.
///
/// Multi-step writes must be all-or-nothing: a crash or error between two
/// statements otherwise leaves a half-applied change behind.
pub(crate) fn in_transaction<T, F>(db: &Connection, write: F) -> Result<T, String>
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
pub(crate) fn reject_empty_password(password: &str, label: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

/// Enforce a minimum length for a password being created or changed.
pub(crate) fn require_min_length(password: &str, label: &str, min_chars: usize) -> Result<(), String> {
    reject_empty_password(password, label)?;
    if password.chars().count() < min_chars {
        return Err(format!(
            "{label} must be at least {min_chars} characters"
        ));
    }
    Ok(())
}


/// Seal pending log entries. Best effort: a failure here must not block the
/// operation that logged, and anything left pending is sealed next time.
pub(crate) fn seal_log(db: &Connection, dek: &[u8; 32]) {
    if let Err(error) = activity::seal_pending(db, dek) {
        eprintln!("Encra could not seal the activity log: {error}");
    }
}
