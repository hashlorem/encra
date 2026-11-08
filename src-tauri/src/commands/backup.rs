//! Backup export and import, and the password-sealed envelope around them.

use base64::Engine;
use zeroize::Zeroize;

use crate::db::*;
use crate::util::fill_random;
use crate::vault::{self, AppState};
use crate::{activity, backup};

#[tauri::command]
pub(crate) fn export_backup(state: tauri::State<AppState>, backup_password: String) -> Result<String, String> {
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
pub(crate) const BACKUP_ENVELOPE: &str = "encra-backup:2";
pub(crate) const BACKUP_AAD: &str = "encra:v1:backup";

pub(crate) fn seal_backup(json: &str, backup_password: &str) -> Result<String, String> {
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
pub(crate) fn open_backup(bundled: &str, backup_password: &str) -> Result<zeroize::Zeroizing<String>, String> {
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
pub(crate) fn import_backup(state: tauri::State<AppState>, bundled: String, backup_password: String) -> Result<(), String> {
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
