//! Backup export and import, and the password-sealed envelope around them.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::Serialize;
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::files::{file_name, read_text_capped, write_private};
use crate::db::*;
use crate::util::{fill_random, uuid_v4};
use crate::vault::{self, AppState};
use crate::{activity, backup};

/// Backups are small text files; anything bigger was picked by mistake.
const MAX_BACKUP_BYTES: u64 = 256 * 1024 * 1024;
/// How long a picked backup file waits for its password.
const STAGE_TTL: Duration = Duration::from_secs(10 * 60);

/// Seal a backup and save it where the person chooses. The save dialog opens
/// from Rust, so the webview never supplies a path. None if they cancel.
#[tauri::command]
pub(crate) async fn export_backup(app: tauri::AppHandle, backup_password: String) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let state = app.state::<AppState>();
    require_unlocked(&state)?;
    require_min_length(&backup_password, "Backup password", MIN_BACKUP_PASSWORD_CHARS)?;
    let today: String = {
        let db = require_db(&state)?;
        db.query_row("SELECT date('now', 'localtime')", [], |r| r.get(0)).map_err(|e| e.to_string())?
    };
    let Some(picked) = app
        .dialog()
        .file()
        .set_title("Save a backup")
        .set_file_name(format!("encra-backup-{today}.encra"))
        .add_filter("Encra backup", &["encra"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let dest = picked.into_path().map_err(|e| e.to_string())?;

    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let data = backup::collect_all(&db, &key)?;
    let json = zeroize::Zeroizing::new(serde_json::to_string(&data).map_err(|e| e.to_string())?);
    let bundled = seal_backup(&json, &backup_password)?;
    write_private(&dest, bundled.as_bytes())?;

    activity::log_action(&db, "backup_export", "vault exported");
    seal_log(&db, &key);
    Ok(Some(file_name(&dest)))
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

/// A backup file read in Rust, waiting for its password. Cleared on seal.
#[derive(Default)]
pub(crate) struct PendingBackup(pub(crate) Mutex<Option<StagedBackup>>);

pub(crate) struct StagedBackup {
    token: String,
    at: Instant,
    contents: Zeroizing<String>,
}

impl PendingBackup {
    /// Hold a picked file's contents and return the token that claims them.
    pub(crate) fn stage(&self, contents: String) -> Result<String, String> {
        let token = uuid_v4();
        let staged = StagedBackup { token: token.clone(), at: Instant::now(), contents: Zeroizing::new(contents) };
        *self.0.lock().map_err(|e| e.to_string())? = Some(staged);
        Ok(token)
    }

    /// Run `act` on the contents for `token`, clearing them only when `act`
    /// succeeds (check, act, then consume): a wrong backup password can be
    /// retried without picking the file again.
    pub(crate) fn with_staged<T>(&self, token: &str, now: Instant, act: impl FnOnce(&str) -> Result<T, String>) -> Result<T, String> {
        let mut pending = self.0.lock().map_err(|e| e.to_string())?;
        let contents = match pending.as_ref() {
            Some(staged) if staged.token == token && now.duration_since(staged.at) < STAGE_TTL => &staged.contents,
            _ => return Err("that backup file is no longer open; choose it again".into()),
        };
        let result = act(contents)?;
        *pending = None;
        Ok(result)
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut pending) = self.0.lock() {
            *pending = None;
        }
    }
}

#[derive(Serialize)]
pub(crate) struct PickedFile {
    token: String,
    name: String,
}

/// Pick a backup file with the system dialog and read it in Rust. Nothing is
/// restored until `import_backup` gets the token back with the password.
#[tauri::command]
pub(crate) async fn pick_backup_file(app: tauri::AppHandle) -> Result<Option<PickedFile>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_unlocked(&app.state::<AppState>())?;
    let Some(picked) = app
        .dialog()
        .file()
        .set_title("Restore a backup")
        .add_filter("Encra backup", &["encra", "cobrypt", "kpt"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    let contents = read_text_capped(&path, MAX_BACKUP_BYTES)?;
    let token = app.state::<PendingBackup>().stage(contents)?;
    Ok(Some(PickedFile { token, name: file_name(&path) }))
}

#[tauri::command]
pub(crate) fn import_backup(
    state: tauri::State<AppState>,
    pending: tauri::State<PendingBackup>,
    token: String,
    backup_password: String,
) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    reject_empty_password(&backup_password, "Backup password")?;
    pending.with_staged(&token, Instant::now(), |bundled| {
        let db = require_db(&state)?;
        let json = open_backup(bundled, &backup_password)?;
        let data: backup::VaultBackup = serde_json::from_str(&json).map_err(|_| "invalid backup format — unreadable contents".to_string())?;

        // Plain text throughout, then sealed row by row under this vault's key
        // as each row gets its new id. A 1.0 payload this key cannot decrypt is
        // rejected rather than written back as unreadable bytes.
        let prepared = backup::prepare_for_import(data, &key)?;
        backup::restore_all(&db, &key, &prepared)?;
        activity::log_action(&db, "backup_import", "vault data imported");
        seal_log(&db, &key);
        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_picked_backup_is_claimed_once_by_its_token() {
        let read = |contents: &str| Ok(contents.to_string());
        let pending = PendingBackup::default();
        let token = pending.stage("contents".into()).unwrap();
        assert!(pending.with_staged("not-the-token", Instant::now(), read).is_err());
        assert!(pending.with_staged(&token, Instant::now() + STAGE_TTL, read).is_err(), "expired");

        // A wrong password fails the import and keeps the file for a retry.
        let wrong_password = |_: &str| -> Result<(), String> { Err("wrong backup password".into()) };
        assert!(pending.with_staged(&token, Instant::now(), wrong_password).is_err());
        assert_eq!(pending.with_staged(&token, Instant::now(), read).unwrap(), "contents");
        assert!(pending.with_staged(&token, Instant::now(), read).is_err(), "only once it worked");

        let token = pending.stage("contents".into()).unwrap();
        pending.clear();
        assert!(pending.with_staged(&token, Instant::now(), read).is_err(), "sealing clears it");
    }
}
