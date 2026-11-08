//! Toolbox: the Nmap parser and the command library.

use tauri::Manager;

use crate::commands::files::{file_name, read_text_capped, take_dropped};
use crate::db::*;
use crate::util::{check_field, uuid_v4};
use crate::vault::AppState;
use crate::{fields, kb, nmap};

// ===== Nmap =====

/// A scan file and its name, for the parser page.
#[derive(serde::Serialize)]
pub(crate) struct OpenedScan {
    name: String,
    scan: nmap::NmapScan,
}

fn open_scan(path: &std::path::Path) -> Result<OpenedScan, String> {
    let xml = read_text_capped(path, nmap::MAX_XML_BYTES as u64)?;
    Ok(OpenedScan { name: file_name(path), scan: nmap::parse_nmap_xml(&xml)? })
}

/// The first XML file among dropped paths.
pub(crate) fn first_xml(paths: &[std::path::PathBuf]) -> Option<&std::path::PathBuf> {
    paths.iter().find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")))
}

/// Pick a scan with the system dialog, opened from Rust. None if cancelled.
#[tauri::command]
pub(crate) async fn open_nmap_file(app: tauri::AppHandle) -> Result<Option<OpenedScan>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_unlocked(&app.state::<AppState>())?;
    let Some(picked) = app.dialog().file().set_title("Open an Nmap scan").add_filter("Nmap XML", &["xml"]).blocking_pick_file() else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || open_scan(&path)).await.map_err(|e| e.to_string())?.map(Some)
}

/// Parse the scan most recently dropped on the window.
#[tauri::command]
pub(crate) async fn open_dropped_nmap(app: tauri::AppHandle) -> Result<Option<OpenedScan>, String> {
    require_unlocked(&app.state::<AppState>())?;
    let paths = take_dropped(&app)?;
    if paths.is_empty() {
        return Ok(None);
    }
    let path = first_xml(&paths).ok_or("only Nmap XML files can be parsed")?.clone();
    tauri::async_runtime::spawn_blocking(move || open_scan(&path)).await.map_err(|e| e.to_string())?.map(Some)
}

// ===== Command KB =====

#[tauri::command]
pub(crate) fn add_kb_entry(state: tauri::State<AppState>, input: kb::KBInput) -> Result<kb::KBEntry, String> {
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
pub(crate) fn get_kb_entries(state: tauri::State<AppState>) -> Result<Vec<kb::KBEntry>, String> {
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
pub(crate) fn delete_kb_entry(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    db.execute("DELETE FROM kb_entries WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_first_xml_picks_the_scan_among_drops() {
        let paths = [PathBuf::from("/tmp/notes.txt"), PathBuf::from("/tmp/Scan.XML"), PathBuf::from("/tmp/b.xml")];
        assert_eq!(first_xml(&paths), Some(&PathBuf::from("/tmp/Scan.XML")));
        assert_eq!(first_xml(&[PathBuf::from("/tmp/capture.pcap")]), None);
        assert_eq!(first_xml(&[]), None);
    }
}
