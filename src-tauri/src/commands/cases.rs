//! Cases: their notes, and the indicators and timeline drawn from the notes
//! and evidence.

use std::path::Path;

use rusqlite::Connection;
use tauri::Manager;

use crate::commands::evidence::EvidenceDir;
use crate::commands::files::{file_name, write_private};
use crate::db::*;
use crate::util::{check_field, uuid_v4};
use crate::vault::AppState;
use crate::{activity, evidence, fields, indicators, journal};

// ===== Journal =====

#[tauri::command]
pub(crate) fn create_project(state: tauri::State<AppState>, input: journal::ProjectInput) -> Result<journal::Project, String> {
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
pub(crate) fn get_projects(state: tauri::State<AppState>) -> Result<Vec<journal::Project>, String> {
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
pub(crate) fn delete_project(state: tauri::State<AppState>, dir: tauri::State<EvidenceDir>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let evidence_ids = delete_project_records(&db, &id)?;
    evidence::remove_files(&dir.0, &evidence_ids);
    Ok(())
}

/// The case, its entries and its evidence records disappear together: a crash
/// between deletes used to leave orphaned entries behind. Returns the evidence
/// whose files to remove now that the records are gone.
pub(crate) fn delete_project_records(db: &Connection, id: &str) -> Result<Vec<String>, String> {
    in_transaction(db, || {
        let evidence_ids = evidence::ids_in_case(db, id)?;
        evidence::delete_records(db, &evidence_ids)?;
        db.execute("DELETE FROM journal_entries WHERE project_id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        db.execute("DELETE FROM projects WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        Ok(evidence_ids)
    })
}


#[tauri::command]
pub(crate) fn add_entry(state: tauri::State<AppState>, input: journal::EntryInput) -> Result<journal::JournalEntry, String> {
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

/// A case's entries, newest first, decrypted.
pub(crate) fn entries_of(db: &Connection, key: &[u8; 32], project_id: &str) -> Result<Vec<journal::JournalEntry>, String> {
    let mut stmt = db.prepare("SELECT id, project_id, title, content, entry_type, severity, created_at FROM journal_entries WHERE project_id = ?1 ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let results = stmt.query_map(rusqlite::params![project_id], |row| {
        let id: String = row.get(0)?;
        let open = |column: &str, stored: String| fields::open_to_string(key, "journal_entries", &id, column, &stored);
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
pub(crate) fn get_entries(state: tauri::State<AppState>, project_id: String) -> Result<Vec<journal::JournalEntry>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    entries_of(&db, &key, &project_id)
}

#[tauri::command]
pub(crate) fn delete_entry(state: tauri::State<AppState>, id: String) -> Result<(), String> {
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
pub(crate) fn insert_entries(
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
pub(crate) fn add_entries(state: tauri::State<AppState>, inputs: Vec<journal::EntryInput>) -> Result<usize, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    insert_entries(&db, &key, &inputs)
}

// ===== Indicators and timeline =====

/// What indicators are pulled from: each entry (title and text), and each
/// evidence file (its name, hashes and custody notes).
pub(crate) fn case_sources(db: &Connection, key: &[u8; 32], dir: &Path, project_id: &str) -> Result<Vec<(String, String)>, String> {
    let mut sources: Vec<(String, String)> = entries_of(db, key, project_id)?
        .into_iter()
        .rev()
        .map(|entry| (entry.title.clone(), format!("{}\n{}", entry.title, entry.content)))
        .collect();
    for item in evidence::list(db, key, dir, project_id)? {
        let notes: Vec<String> = evidence::custody(db, key, &item.id)?.events.into_iter().filter(|e| e.action == "note").map(|e| e.detail).collect();
        let text = format!("{}\n{}\n{}\n{}\n{}", item.name, item.hashes.sha256, item.hashes.sha1, item.hashes.md5, notes.join("\n"));
        sources.push((item.name, text));
    }
    Ok(sources)
}

#[tauri::command]
pub(crate) fn case_indicators(state: tauri::State<AppState>, dir: tauri::State<EvidenceDir>, project_id: String) -> Result<Vec<indicators::Indicator>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    Ok(indicators::extract(&case_sources(&db, &key, &dir.0, &project_id)?))
}

/// Save a case's indicators as CSV where the person chooses, through a save
/// dialog opened from Rust. None if they cancel.
#[tauri::command]
pub(crate) async fn export_indicators(app: tauri::AppHandle, project_id: String, defanged: bool) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let state = app.state::<AppState>();
    let today: String = {
        require_unlocked(&state)?;
        let db = require_db(&state)?;
        db.query_row("SELECT date('now', 'localtime')", [], |r| r.get(0)).map_err(|e| e.to_string())?
    };
    let Some(picked) = app
        .dialog()
        .file()
        .set_title("Export indicators")
        .set_file_name(format!("indicators-{today}.csv"))
        .add_filter("CSV", &["csv"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let dest = picked.into_path().map_err(|e| e.to_string())?;
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let dir = app.state::<EvidenceDir>().0.clone();
    let csv = indicators::to_csv(&indicators::extract(&case_sources(&db, &key, &dir, &project_id)?), defanged)?;
    write_private(&dest, csv.as_bytes())?;
    activity::log_action(&db, "indicators_exported", "exported a case's indicators");
    seal_log(&db, &key);
    Ok(Some(file_name(&dest)))
}

/// One event on a case's timeline.
#[derive(Debug, serde::Serialize, PartialEq)]
pub(crate) struct TimelineEvent {
    pub(crate) at: String,
    /// "case", "entry" or "evidence".
    pub(crate) source: &'static str,
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) entry_type: Option<String>,
    pub(crate) severity: Option<String>,
    /// For evidence: added, verified, exported, note, …
    pub(crate) action: Option<String>,
}

/// The case opened, its entries and its evidence custody, oldest first.
pub(crate) fn timeline(db: &Connection, key: &[u8; 32], dir: &Path, project_id: &str) -> Result<Vec<TimelineEvent>, String> {
    let (name, description, opened): (String, String, String) = db
        .query_row("SELECT name, COALESCE(description, ''), created_at FROM projects WHERE id = ?1", [project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|_| "that case no longer exists".to_string())?;
    let open = |column: &str, stored: &str| fields::open_to_string(key, "projects", project_id, column, stored);
    let mut events = vec![TimelineEvent {
        at: opened,
        source: "case",
        title: open("name", &name).unwrap_or_else(|_| "[unreadable]".into()),
        detail: open("description", &description).unwrap_or_default(),
        entry_type: None,
        severity: None,
        action: None,
    }];
    for entry in entries_of(db, key, project_id)? {
        events.push(TimelineEvent { at: entry.created_at, source: "entry", title: entry.title, detail: entry.content, entry_type: Some(entry.entry_type), severity: Some(entry.severity), action: None });
    }
    for item in evidence::list(db, key, dir, project_id)? {
        for event in evidence::custody(db, key, &item.id)?.events {
            events.push(TimelineEvent { at: event.at, source: "evidence", title: item.name.clone(), detail: event.detail, entry_type: None, severity: None, action: Some(event.action) });
        }
    }
    // Every time is "YYYY-MM-DD HH:MM:SS" in UTC, so text order is time order.
    events.sort_by(|a, b| a.at.cmp(&b.at));
    Ok(events)
}

#[tauri::command]
pub(crate) fn case_timeline(state: tauri::State<AppState>, dir: tauri::State<EvidenceDir>, project_id: String) -> Result<Vec<TimelineEvent>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    timeline(&db, &key, &dir.0, &project_id)
}

