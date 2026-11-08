//! Agent access commands and the menu-bar indicator.

use std::sync::Arc;
use rusqlite::Connection;
use tauri::Manager;

use crate::db::*;
use crate::vault::AppState;
use crate::{activity, agent};

pub(crate) const AGENT_TRAY: &str = "agent";
pub(crate) const TRAY_IDLE: &[u8] = include_bytes!("../../icons/tray/agent.png");
pub(crate) const TRAY_WAITING: &[u8] = include_bytes!("../../icons/tray/agent-waiting.png");

pub(crate) fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(crate) fn show_waiting_in_menu_bar(app: &tauri::AppHandle, waiting: usize) {
    let Some(tray) = app.tray_by_id(AGENT_TRAY) else { return };
    let icon = if waiting > 0 { TRAY_WAITING } else { TRAY_IDLE };
    if let Ok(image) = tauri::image::Image::from_bytes(icon) {
        let _ = tray.set_icon(Some(image));
        let _ = tray.set_icon_as_template(true);
    }
    let _ = tray.set_title((waiting > 0).then(|| waiting.to_string()));
    let _ = tray.set_tooltip(Some(match waiting {
        0 => "Encra: agent access is on".to_string(),
        1 => "Encra: 1 agent request waiting".to_string(),
        n => format!("Encra: {n} agent requests waiting"),
    }));
}

pub(crate) fn agent_access_enabled(db: &Connection) -> bool {
    db.query_row("SELECT value FROM vault_config WHERE key = 'agent_access'", [], |row| row.get::<_, String>(0))
        .map(|value| value == "on")
        .unwrap_or(false)
}

#[derive(serde::Serialize)]
pub(crate) struct AgentStatus {
    enabled: bool,
    listening: bool,
    /// The binary to put on PATH, as `encra`.
    binary: String,
}

pub(crate) fn agent_status_of(db: &Connection, hub: &agent::server::Hub) -> AgentStatus {
    AgentStatus {
        enabled: agent_access_enabled(db),
        listening: hub.is_running(),
        binary: std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}

#[tauri::command]
pub(crate) fn agent_status(state: tauri::State<AppState>, hub: tauri::State<Arc<agent::server::Hub>>) -> Result<AgentStatus, String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    Ok(agent_status_of(&db, &hub))
}

#[tauri::command]
pub(crate) fn set_agent_access(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    hub: tauri::State<Arc<agent::server::Hub>>,
    enabled: bool,
) -> Result<AgentStatus, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    if enabled {
        hub.start(&agent::sock::default_dir())?;
    } else {
        hub.stop();
    }
    db.execute(
        "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('agent_access', ?1)",
        [if enabled { "on" } else { "off" }],
    )
    .map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id(AGENT_TRAY) {
        let _ = tray.set_visible(enabled);
    }
    activity::log_action(&db, "agent_access", if enabled { "agent access turned on" } else { "agent access turned off" });
    seal_log(&db, &key);
    Ok(agent_status_of(&db, &hub))
}

/// A waiting request plus how each reference matches your logins. The
/// matches are for you only; the caller never receives them.
#[derive(serde::Serialize)]
pub(crate) struct PendingView {
    #[serde(flatten)]
    info: agent::server::PendingInfo,
    matches: Vec<agent::refs::Match>,
}

#[tauri::command]
pub(crate) fn agent_pending(state: tauri::State<AppState>, hub: tauri::State<Arc<agent::server::Hub>>) -> Result<Vec<PendingView>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    Ok(hub
        .pending()
        .into_iter()
        .map(|info| PendingView {
            matches: info.references.iter().map(|r| agent::refs::preview(&db, &key, r)).collect(),
            info,
        })
        .collect())
}

/// Answer one waiting request. Only reachable unlocked, so a request can
/// never resolve while the vault is sealed.
#[tauri::command]
pub(crate) fn agent_decide(
    state: tauri::State<AppState>,
    hub: tauri::State<Arc<agent::server::Hub>>,
    id: String,
    approve: bool,
    choices: Option<std::collections::HashMap<String, String>>,
    remember: Option<bool>,
) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    let choices = choices.unwrap_or_default();
    let result = decide_agent_request(&db, &key, &hub, &id, approve, &choices, remember.unwrap_or(false));
    seal_log(&db, &key);
    result
}

/// `choices` maps a reference to a login the approver picked for it (for a
/// name that matched nothing, or more than one). With `remember`, a picked
/// login is saved as what that name means from now on.
pub(crate) fn decide_agent_request(
    db: &Connection,
    key: &[u8; 32],
    hub: &agent::server::Hub,
    id: &str,
    approve: bool,
    choices: &std::collections::HashMap<String, String>,
    remember: bool,
) -> Result<(), String> {
    use agent::server::Decision;
    let (info, reply) = hub.take(id).ok_or("that request is no longer waiting")?;
    let place = format!("{} in {}", info.executable, info.cwd);
    if !approve {
        let _ = reply.send(Decision::Deny);
        activity::log_action(db, "agent_denied", &format!("denied {place}"));
        return Ok(());
    }

    let mut values = Vec::with_capacity(info.references.len());
    let mut given = Vec::with_capacity(info.references.len());
    for reference in &info.references {
        let chosen = choices.get(reference).map(String::as_str);
        match agent::refs::resolve(db, key, reference, chosen) {
            Ok((login_id, value)) => {
                let field = agent::refs::parse(reference).map(|r| agent::refs::field_name(r.field)).unwrap_or("?");
                // The login's id, not its name: the log is readable while sealed.
                given.push(format!("{field} of login {}", &login_id[..login_id.len().min(8)]));
                values.push((reference.clone(), zeroize::Zeroizing::new(value.as_bytes().to_vec())));
            }
            Err(error) => {
                let _ = reply.send(Decision::Fail(error.clone()));
                activity::log_action(db, "agent_failed", &format!("approved but a reference could not be resolved: {place}"));
                return Err(error);
            }
        }
    }
    if remember {
        for (reference, login) in choices {
            if let Ok(agent::refs::Reference { target: agent::refs::Target::Name(name), .. }) = agent::refs::parse(reference) {
                agent::refs::remember(db, key, &name, login)?;
            }
        }
    }
    if reply.send(Decision::Approve(values)).is_err() {
        activity::log_action(db, "agent_cancelled", &format!("approved after the caller left: {place}"));
        return Err("the caller is no longer waiting".into());
    }
    activity::log_action(db, "agent_approved", &format!("gave {} to {place}", given.join(", ")));
    Ok(())
}
