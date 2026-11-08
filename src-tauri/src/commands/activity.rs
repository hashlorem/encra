//! The activity log as the Activity page reads it.

use crate::db::*;
use crate::vault::AppState;
use crate::activity;

use rusqlite::Connection;

/// Entries per page of the Activity page.
pub(crate) const PAGE: usize = 100;

#[derive(serde::Serialize)]
pub(crate) struct ActivityLog {
    entries: Vec<activity::ActivityEntry>,
    chain: activity::ChainStatus,
    has_more: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct ActivityPage {
    entries: Vec<activity::ActivityEntry>,
    has_more: bool,
}

/// Newest first, one page, starting below `before` (a `seq`) when given.
pub(crate) fn page(db: &Connection, before: Option<i64>) -> Result<(Vec<activity::ActivityEntry>, bool), String> {
    let mut stmt = db
        .prepare(
            "SELECT id, seq, action, detail, timestamp FROM activity_log
             WHERE ?1 IS NULL OR seq < ?1 ORDER BY seq DESC, rowid DESC LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;
    let mut entries = stmt
        .query_map(rusqlite::params![before, PAGE as i64 + 1], |row| {
            Ok(activity::ActivityEntry { id: row.get(0)?, seq: row.get(1)?, action: row.get(2)?, detail: row.get(3)?, timestamp: row.get(4)? })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let has_more = entries.len() > PAGE;
    entries.truncate(PAGE);
    Ok((entries, has_more))
}

#[tauri::command]
pub(crate) fn get_activity_log(state: tauri::State<AppState>) -> Result<ActivityLog, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    // Verify before sealing, so new entries are never sealed on top of a
    // chain that was tampered with (that would launder the tampering).
    let mut chain = activity::verify_chain(&db, &key)?;
    if chain.intact && chain.pending > 0 {
        seal_log(&db, &key);
        chain = activity::verify_chain(&db, &key)?;
    }
    let (entries, has_more) = page(&db, None)?;
    Ok(ActivityLog { entries, chain, has_more })
}

/// The page of entries older than `before_seq`.
#[tauri::command]
pub(crate) fn get_activity_older(state: tauri::State<AppState>, before_seq: i64) -> Result<ActivityPage, String> {
    require_unlocked(&state)?;
    let db = require_db(&state)?;
    let (entries, has_more) = page(&db, Some(before_seq))?;
    Ok(ActivityPage { entries, has_more })
}
