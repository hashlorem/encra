//! Importing from another password manager. The export is picked and read in
//! Rust and held here until the person confirms; the page gets a preview of
//! names and counts and a token, never a password.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::Manager;

use crate::commands::files::{file_name, read_text_capped};
use crate::db::*;
use crate::util::uuid_v4;
use crate::vault::AppState;
use crate::{activity, import};

/// How long a previewed import waits for Add, and how long afterwards the
/// export can still be deleted from Encra.
const STAGE_TTL: Duration = Duration::from_secs(10 * 60);
const SAMPLE: usize = 6;

pub(crate) struct StagedImport {
    token: String,
    at: Instant,
    path: PathBuf,
    parsed: import::Parsed,
}

/// The previewed import, and afterwards the export file it came from (for
/// "Delete the export"). Both are cleared when the vault seals.
#[derive(Default)]
pub(crate) struct PendingImport {
    staged: Mutex<Option<StagedImport>>,
    imported_file: Mutex<Option<(Instant, PathBuf)>>,
}

impl PendingImport {
    pub(crate) fn stage(&self, path: PathBuf, parsed: import::Parsed) -> Result<String, String> {
        let token = uuid_v4();
        *self.staged.lock().map_err(|e| e.to_string())? = Some(StagedImport { token: token.clone(), at: Instant::now(), path, parsed });
        Ok(token)
    }

    /// Run `act` on the staged import for `token`, and only clear it if `act`
    /// succeeds: check, act, then consume. A failed write leaves the preview
    /// in place to retry; a wrong or stale token gets nothing.
    pub(crate) fn with_staged<T>(&self, token: &str, now: Instant, act: impl FnOnce(&std::path::Path, &import::Parsed) -> Result<T, String>) -> Result<T, String> {
        let mut staged = self.staged.lock().map_err(|e| e.to_string())?;
        let current = match staged.as_ref() {
            Some(s) if s.token == token && now.duration_since(s.at) < STAGE_TTL => s,
            _ => return Err("that import is no longer open; choose the file again".into()),
        };
        let result = act(&current.path, &current.parsed)?;
        *staged = None;
        Ok(result)
    }

    pub(crate) fn remember_imported(&self, path: PathBuf) {
        if let Ok(mut file) = self.imported_file.lock() {
            *file = Some((Instant::now(), path));
        }
    }

    /// The export just imported, if it is still recent. Taken once.
    pub(crate) fn take_imported(&self, now: Instant) -> Option<PathBuf> {
        match self.imported_file.lock().ok()?.take() {
            Some((at, path)) if now.duration_since(at) < STAGE_TTL => Some(path),
            _ => None,
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut staged) = self.staged.lock() {
            *staged = None;
        }
        if let Ok(mut file) = self.imported_file.lock() {
            *file = None;
        }
    }
}

#[derive(Serialize)]
pub(crate) struct SampleLogin {
    service: String,
    username: String,
}

/// What the page shows before anything is added. No passwords, no 2FA keys.
#[derive(Serialize)]
pub(crate) struct ImportPreview {
    token: String,
    file_name: String,
    source: &'static str,
    ready: usize,
    with_totp: usize,
    totp_unusable: usize,
    skipped: import::Skipped,
    sample: Vec<SampleLogin>,
}

pub(crate) fn preview(token: String, file_name: String, parsed: &import::Parsed) -> ImportPreview {
    ImportPreview {
        token,
        file_name,
        source: parsed.format.label(),
        ready: parsed.logins.len(),
        with_totp: parsed.logins.iter().filter(|l| l.totp.is_some()).count(),
        totp_unusable: parsed.totp_unusable,
        skipped: parsed.skipped.clone(),
        sample: parsed.logins.iter().take(SAMPLE).map(|l| SampleLogin { service: l.service.clone(), username: l.username.clone() }).collect(),
    }
}

/// Pick an export with the system dialog, read and parse it in Rust, and hold
/// it for Add. None if the dialog is cancelled.
#[tauri::command]
pub(crate) async fn pick_import_file(app: tauri::AppHandle) -> Result<Option<ImportPreview>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_unlocked(&app.state::<AppState>())?;
    let Some(picked) = app.dialog().file().set_title("Import passwords").add_filter("CSV export", &["csv"]).blocking_pick_file() else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    let parse_path = path.clone();
    let mut parsed = tauri::async_runtime::spawn_blocking(move || {
        let text = zeroize::Zeroizing::new(read_text_capped(&parse_path, import::MAX_IMPORT_BYTES)?);
        import::parse(&text)
    })
    .await
    .map_err(|e| e.to_string())??;

    let state = app.state::<AppState>();
    {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        import::drop_duplicates(&db, &key, &mut parsed)?;
    }
    let mut shown = preview(String::new(), file_name(&path), &parsed);
    shown.token = app.state::<PendingImport>().stage(path, parsed)?;
    Ok(Some(shown))
}

/// Add every previewed login, all at once.
#[tauri::command]
pub(crate) fn confirm_import(state: tauri::State<AppState>, pending: tauri::State<PendingImport>, token: String) -> Result<usize, String> {
    let key = require_unlocked(&state)?;
    let (added, path) = pending.with_staged(&token, Instant::now(), |path, parsed| {
        let db = require_db(&state)?;
        let added = import::commit(&db, &key, &parsed.logins)?;
        activity::log_action(&db, "import", &format!("added {added} logins from {}", parsed.format.label()));
        seal_log(&db, &key);
        Ok((added, path.to_path_buf()))
    })?;
    pending.remember_imported(path);
    Ok(added)
}

#[tauri::command]
pub(crate) fn cancel_import(pending: tauri::State<PendingImport>) {
    pending.clear();
}

/// Delete the export that was just imported. The path is the one Rust read,
/// never one from the page, and only for a few minutes after the import.
#[tauri::command]
pub(crate) fn delete_import_file(state: tauri::State<AppState>, pending: tauri::State<PendingImport>) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let path = pending.take_imported(Instant::now()).ok_or("there is no recent import to delete")?;
    std::fs::remove_file(&path).map_err(|e| format!("could not delete that file: {e}"))?;
    let db = require_db(&state)?;
    activity::log_action(&db, "import_file_deleted", "deleted the export after importing it");
    seal_log(&db, &key);
    Ok(file_name(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,hashlorem,gh-secret-pass,,otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP\n";

    #[test]
    fn test_a_previewed_import_is_claimed_once_and_cleared_on_seal() {
        let pending = PendingImport::default();
        let count = |_: &std::path::Path, parsed: &import::Parsed| Ok(parsed.logins.len());
        let token = pending.stage(PathBuf::from("/tmp/export.csv"), import::parse(CSV).unwrap()).unwrap();
        assert!(pending.with_staged("wrong", Instant::now(), count).is_err());
        assert!(pending.with_staged(&token, Instant::now() + STAGE_TTL, count).is_err(), "expired");

        // A failed write keeps the preview for a retry; success clears it.
        let failing = |_: &std::path::Path, _: &import::Parsed| -> Result<usize, String> { Err("disk full".into()) };
        assert!(pending.with_staged(&token, Instant::now(), failing).is_err());
        assert_eq!(pending.with_staged(&token, Instant::now(), count).unwrap(), 1, "still there after a failure");
        assert!(pending.with_staged(&token, Instant::now(), count).is_err(), "gone after it succeeded");

        pending.remember_imported(PathBuf::from("/tmp/export.csv"));
        pending.clear();
        assert!(pending.take_imported(Instant::now()).is_none(), "sealing forgets the export too");
        pending.remember_imported(PathBuf::from("/tmp/export.csv"));
        assert!(pending.take_imported(Instant::now() + STAGE_TTL).is_none(), "only shortly after importing");
        pending.remember_imported(PathBuf::from("/tmp/export.csv"));
        assert!(pending.take_imported(Instant::now()).is_some());
        assert!(pending.take_imported(Instant::now()).is_none(), "once");
    }

    #[test]
    fn test_the_preview_carries_names_and_counts_but_no_secrets() {
        let parsed = import::parse(CSV).unwrap();
        let json = serde_json::to_string(&preview("t".into(), "Passwords.csv".into(), &parsed)).unwrap();
        assert!(json.contains("GitHub") && json.contains("hashlorem"));
        assert!(!json.contains("gh-secret-pass"), "no password");
        assert!(!json.contains("JBSWY3DPEHPK3PXP"), "no 2FA key");
        assert!(json.contains("\"with_totp\":1"));
    }
}

