//! The vault check-up page: the report, and checking every login against
//! known breaches.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::db::*;
use crate::vault::AppState;
use crate::{activity, checkup, credentials, hibp};

#[tauri::command]
pub(crate) fn vault_checkup(state: tauri::State<AppState>) -> Result<checkup::Checkup, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    checkup::run(&db, &key)
}

/// Set while a "check all" runs, so a second one can't start beside it (the
/// page that started the first may have been left and opened again).
static CHECKING_ALL: AtomicBool = AtomicBool::new(false);

/// Holds CHECKING_ALL for one run and lets it go however the run ends.
struct OneRun;

impl OneRun {
    fn start() -> Result<Self, String> {
        CHECKING_ALL
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| OneRun)
            .map_err(|_| "a breach check is already running".to_string())
    }
}

impl Drop for OneRun {
    fn drop(&mut self) {
        CHECKING_ALL.store(false, Ordering::SeqCst);
    }
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
    let _run = OneRun::start()?;
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
            // A login deleted during the run, or one whose password can't be
            // read, is skipped rather than ending the whole check.
            credentials::reveal_password(&db, &key, id).unwrap_or_default()
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
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    activity::log_action(&db, "breach_check_all", &format!("checked {checked} passwords against known breaches"));
    seal_log(&db, &key);
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_one_check_all_runs_at_a_time() {
        let first = OneRun::start().unwrap();
        assert_eq!(OneRun::start().err().unwrap(), "a breach check is already running");
        drop(first);
        let again = OneRun::start();
        assert!(again.is_ok(), "free again once the first run ends, however it ended");
    }
}
