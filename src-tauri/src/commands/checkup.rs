//! The vault check-up page: the report, and checking every login against
//! known breaches.

use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::db::*;
use crate::vault::AppState;
use crate::{checkup, credentials, hibp};

#[tauri::command]
pub(crate) fn vault_checkup(state: tauri::State<AppState>) -> Result<checkup::Checkup, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    checkup::run(&db, &key)
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct CheckProgress {
    done: usize,
    total: usize,
}

/// Check every login's password against known breaches, one at a time, and
/// remember each result as it comes. Only the first 5 characters of each
/// password's SHA-1 hash leave this Mac. Stops if the vault seals.
#[tauri::command]
pub(crate) async fn check_all_breaches(app: tauri::AppHandle) -> Result<usize, String> {
    let state = app.state::<AppState>();
    let ids: Vec<String> = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        credentials::list_summaries(&db, &key)?.into_iter().map(|c| c.id).collect()
    };
    let total = ids.len();
    let mut checked = 0;
    for (done, id) in ids.iter().enumerate() {
        let password = {
            let key = require_unlocked(&state)?;
            let db = require_db(&state)?;
            credentials::reveal_password(&db, &key, id)?
        };
        if !password.is_empty() {
            let count = hibp::check_password(&password).await?;
            {
                let key = require_unlocked(&state)?;
                let db = require_db(&state)?;
                credentials::record_breach(&db, &key, id, count)?;
            }
            checked += 1;
            // A pause between requests, to be polite to the service.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = app.emit("checkup-progress", CheckProgress { done: done + 1, total });
    }
    Ok(checked)
}
