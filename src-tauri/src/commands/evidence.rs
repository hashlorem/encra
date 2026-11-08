//! The evidence locker's commands. File paths come from dialogs and drops
//! handled here, never from the webview.

use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Emitter, Manager};

use crate::db::*;
use crate::util::check_field;
use crate::vault::AppState;
use crate::evidence;

/// Where evidence files live, beside the vault.
pub(crate) struct EvidenceDir(pub(crate) PathBuf);

/// Files dropped on the window, held in Rust so the webview never supplies a
/// path. A case claims them shortly after the drop or they are forgotten.
#[derive(Default)]
pub(crate) struct DroppedFiles(pub(crate) Mutex<Option<(std::time::Instant, Vec<PathBuf>)>>);

pub(crate) const DROP_CLAIM_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, serde::Serialize)]
pub(crate) struct EvidenceProgress {
    name: String,
    done: u64,
    total: u64,
}

#[tauri::command]
pub(crate) fn list_evidence(state: tauri::State<AppState>, dir: tauri::State<EvidenceDir>, project_id: String) -> Result<Vec<evidence::Item>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::list(&db, &key, &dir.0, &project_id)
}

/// Read, hash and store each file, then record it. Files are read without
/// holding the database, and the vault is checked again before recording.
pub(crate) async fn add_evidence_files(app: tauri::AppHandle, project_id: String, paths: Vec<PathBuf>, note: String) -> Result<Vec<evidence::Item>, String> {
    let state = app.state::<AppState>();
    require_unlocked(&state)?;
    check_field(&note, "note", evidence::MAX_NOTE_CHARS)?;
    let dir = app.state::<EvidenceDir>().0.clone();
    let mut added = Vec::new();
    for path in paths {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (emitter, staging_dir) = (app.clone(), dir.clone());
        let staged = tauri::async_runtime::spawn_blocking(move || {
            evidence::stage(&staging_dir, &path, &mut |done, total| {
                let _ = emitter.emit("evidence-progress", EvidenceProgress { name: name.clone(), done, total });
            })
        })
        .await
        .map_err(|e| e.to_string())??;
        let key = match require_unlocked(&state) {
            Ok(key) => key,
            Err(error) => {
                evidence::discard(&dir, staged);
                return Err(error);
            }
        };
        let db = require_db(&state)?;
        added.push(evidence::commit(&db, &key, &dir, &project_id, staged, &note)?);
        seal_log(&db, &key);
    }
    Ok(added)
}

/// Pick files with the system dialog, opened from Rust.
#[tauri::command]
pub(crate) async fn add_evidence(app: tauri::AppHandle, project_id: String, note: String) -> Result<Vec<evidence::Item>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_unlocked(&app.state::<AppState>())?;
    let picked = app.dialog().file().set_title("Add evidence").blocking_pick_files().unwrap_or_default();
    let paths = picked.into_iter().filter_map(|p| p.into_path().ok()).collect();
    add_evidence_files(app, project_id, paths, note).await
}

/// Add the files most recently dropped on the window.
#[tauri::command]
pub(crate) async fn add_dropped_evidence(app: tauri::AppHandle, project_id: String, note: String) -> Result<Vec<evidence::Item>, String> {
    let dropped = app.state::<DroppedFiles>().0.lock().map_err(|e| e.to_string())?.take();
    let paths = match dropped {
        Some((at, paths)) if at.elapsed() < DROP_CLAIM_WINDOW => paths,
        _ => return Ok(Vec::new()),
    };
    add_evidence_files(app, project_id, paths, note).await
}

#[tauri::command]
pub(crate) async fn verify_evidence(app: tauri::AppHandle, id: String) -> Result<evidence::Check, String> {
    let state = app.state::<AppState>();
    let dir = app.state::<EvidenceDir>().0.clone();
    let (item, file_key) = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        evidence::open_item(&db, &key, &id)?
    };
    let (emitter, name, total) = (app.clone(), item.name.clone(), item.size);
    let (check_item, check_dir) = (item.clone(), dir.clone());
    let check = tauri::async_runtime::spawn_blocking(move || {
        evidence::check(&check_dir, &check_item.id, &file_key, &check_item.hashes, &mut |done| {
            let _ = emitter.emit("evidence-progress", EvidenceProgress { name: name.clone(), done, total });
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::record_check(&db, &key, &item, &check)?;
    Ok(check)
}

/// Save a checked copy where the person chooses. None if they cancel.
#[tauri::command]
pub(crate) async fn export_evidence(app: tauri::AppHandle, id: String) -> Result<Option<evidence::Check>, String> {
    use tauri_plugin_dialog::DialogExt;
    let state = app.state::<AppState>();
    let dir = app.state::<EvidenceDir>().0.clone();
    let (item, file_key) = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        evidence::open_item(&db, &key, &id)?
    };
    let Some(dest) = app.dialog().file().set_title("Export evidence").set_file_name(&item.name).blocking_save_file() else {
        return Ok(None);
    };
    let dest = dest.into_path().map_err(|e| e.to_string())?;
    let (emitter, name, total) = (app.clone(), item.name.clone(), item.size);
    let (export_item, export_dir) = (item.clone(), dir.clone());
    let check = tauri::async_runtime::spawn_blocking(move || {
        evidence::export_to(&export_dir, &export_item, &file_key, &dest, &mut |done| {
            let _ = emitter.emit("evidence-progress", EvidenceProgress { name: name.clone(), done, total });
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::record_export(&db, &key, &item, &check)?;
    Ok(Some(check))
}

#[tauri::command]
pub(crate) fn evidence_custody(state: tauri::State<AppState>, id: String) -> Result<evidence::Custody, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::custody(&db, &key, &id)
}

#[tauri::command]
pub(crate) fn add_evidence_note(state: tauri::State<AppState>, id: String, note: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::add_note(&db, &key, &id, &note)
}

#[tauri::command]
pub(crate) fn delete_evidence(state: tauri::State<AppState>, dir: tauri::State<EvidenceDir>, id: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    evidence::delete(&db, &dir.0, &id)?;
    seal_log(&db, &key);
    Ok(())
}
