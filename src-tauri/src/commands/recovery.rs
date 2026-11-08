//! Recovery codes and changing the master password.

use zeroize::Zeroize;

use crate::db::*;
use crate::commands::lifecycle::bring_up_to_date;
use crate::vault::{self, AppState, Dek};
use crate::activity;

#[tauri::command]
pub(crate) fn verify_master_password(state: tauri::State<AppState>, password: String) -> Result<bool, String> {
    let db = require_db(&state)?;
    let stored_hash: String = db.query_row(
        "SELECT value FROM vault_config WHERE key = 'password_hash'", [], |r| r.get(0)
    ).map_err(|e| e.to_string())?;
    vault::verify_password(&password, &stored_hash)
}

#[tauri::command]
pub(crate) fn generate_recovery_codes(state: tauri::State<AppState>) -> Result<Vec<String>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    activity::generate_recovery_codes(&db, &key)
}

#[tauri::command]
pub(crate) fn reset_master_password(state: tauri::State<AppState>, recovery_code: String, new_password: String) -> Result<bool, String> {
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
