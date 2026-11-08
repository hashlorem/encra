//! The activity log as the Activity page reads it.

use crate::db::*;
use crate::vault::AppState;
use crate::activity;

#[derive(serde::Serialize)]
pub(crate) struct ActivityLog {
    entries: Vec<activity::ActivityEntry>,
    chain: activity::ChainStatus,
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
    let mut stmt = db.prepare("SELECT id, action, detail, timestamp FROM activity_log ORDER BY seq DESC, rowid DESC LIMIT 100")
        .map_err(|e| e.to_string())?;
    let entries = stmt.query_map([], |row| Ok(activity::ActivityEntry { id: row.get(0)?, action: row.get(1)?, detail: row.get(2)?, timestamp: row.get(3)? }))
        .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
    Ok(ActivityLog { entries, chain })
}
