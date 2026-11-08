#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod totp;
mod hibp;
mod journal;
mod nmap;
mod kb;
mod backup;
mod activity;
mod agent;
mod clipboard;
mod credentials;
mod fields;
mod migrate;
mod qr;
mod evidence;
mod util;
mod paths;
mod db;
mod commands;
#[cfg(test)]
mod tests;

use std::sync::Mutex;
use tauri::{Emitter, Manager};

use clipboard::ClipboardGuard;
use commands::agent::{agent_access_enabled, show_main_window, show_waiting_in_menu_bar, AGENT_TRAY, TRAY_IDLE};
use commands::backup::PendingBackup;
use commands::evidence::EvidenceDir;
use commands::files::DroppedFiles;
use commands::{activity as activity_cmd, agent as agent_cmd, backup as backup_cmd, cases, evidence as evidence_cmd, lifecycle, logins, recovery, toolbox};
use paths::{restrict_permissions, vault_path};
use vault::AppState;

// ===== Startup =====

fn main() {
    // `encra run ...` is the command-line client for agent access. It never
    // starts the app; it talks to the one already running.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("run") {
        std::process::exit(agent::client::main(&args[2..]));
    }

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let db_path = vault_path(app.handle()).map_err(std::io::Error::other)?;
            // Fail loudly instead of panicking: a corrupt or unwritable data
            // directory is a condition the user can act on, not a crash.
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).map_err(std::io::Error::other)?;
            }

            let conn = vault::init_db(&db_path).map_err(std::io::Error::other)?;
            // Defence in depth only: a filesystem that refuses chmod must not
            // keep anyone out of their own vault.
            if let Err(error) = restrict_permissions(&db_path) {
                eprintln!("Encra could not restrict vault permissions: {error}");
            }
            journal::init_journal_tables(&conn).map_err(std::io::Error::other)?;
            kb::init_kb_tables(&conn).map_err(std::io::Error::other)?;
            activity::init_activity_table(&conn).map_err(std::io::Error::other)?;
            agent::refs::init_alias_table(&conn).map_err(std::io::Error::other)?;
            evidence::init_tables(&conn).map_err(std::io::Error::other)?;
            let evidence_dir = evidence::dir_for(&db_path);
            if let Err(error) = evidence::sweep(&conn, &evidence_dir) {
                eprintln!("Encra could not tidy the evidence folder: {error}");
            }
            app.manage(EvidenceDir(evidence_dir));
            app.manage(DroppedFiles::default());
            app.manage(PendingBackup::default());

            // Enable foreign keys
            conn.execute_batch("PRAGMA foreign_keys = ON;")
                .map_err(std::io::Error::other)?;

            app.manage(AppState {
                db: Mutex::new(conn),
                encryption_key: Mutex::new(None),
            });
            app.manage(ClipboardGuard::system());

            // Agent access. The hub exists always; it only listens while the
            // setting is on.
            let notify_handle = app.handle().clone();
            let log_handle = app.handle().clone();
            let hub = agent::server::Hub::new(
                Box::new(move |waiting: usize, arrived: bool| {
                    let _ = notify_handle.emit("agent-request", waiting);
                    show_waiting_in_menu_bar(&notify_handle, waiting);
                    if let Some(window) = notify_handle.get_webview_window("main") {
                        // A count on the Dock icon while anything is waiting.
                        let _ = window.set_badge_count((waiting > 0).then_some(waiting as i64));
                        // Bounce until you open Encra. No focus stealing: macOS
                        // never bounces the app in front, and keystrokes meant
                        // for your terminal must not land in the dialog.
                        if arrived {
                            let _ = window.request_user_attention(Some(tauri::UserAttentionType::Critical));
                        } else if waiting == 0 {
                            let _ = window.request_user_attention(None);
                        }
                    }
                }),
                Box::new(move |action: &str, detail: &str| {
                    if let Some(state) = log_handle.try_state::<AppState>() {
                        if let Ok(db) = state.db.lock() {
                            activity::log_action(&db, action, detail);
                        }
                    }
                }),
                agent::server::REQUEST_TIMEOUT,
            );
            let enabled = app.state::<AppState>().db.lock().map(|db| agent_access_enabled(&db)).unwrap_or(false);
            if enabled {
                if let Err(error) = hub.start(&agent::sock::default_dir()) {
                    eprintln!("Encra could not start agent access: {error}");
                }
            }
            app.manage(hub);

            // Menu-bar icon: there while agent access is on, with a dot and a
            // count while a request waits. Clicking it opens Encra.
            let open = tauri::menu::MenuItem::with_id(app, "open", "Open Encra", true, None::<&str>)?;
            let menu = tauri::menu::Menu::with_items(app, &[&open])?;
            let tray = tauri::tray::TrayIconBuilder::with_id(AGENT_TRAY)
                .icon(tauri::image::Image::from_bytes(TRAY_IDLE)?)
                .icon_as_template(true)
                .tooltip("Encra: agent access is on")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    if event.id() == "open" {
                        show_main_window(app);
                    }
                })
                .build(app)?;
            tray.set_visible(enabled)?;
            Ok(())
        })
        .on_window_event(commands::files::window_event)
        .invoke_handler(tauri::generate_handler![
            logins::list_credentials, logins::get_credential, logins::reveal_password, logins::get_totp,
            logins::copy_credential_field, logins::copy_text, logins::check_credential_breach,
            logins::add_credential, logins::update_credential, logins::delete_credential,
            logins::setup_totp, logins::setup_totp_from_clipboard, logins::setup_totp_from_image, logins::remove_totp,
            logins::check_hibp,
            lifecycle::vault_status, lifecycle::create_vault, lifecycle::unlock_vault, lifecycle::lock_vault,
            lifecycle::safety_copy_exists, lifecycle::delete_safety_copy,
            agent_cmd::agent_status, agent_cmd::set_agent_access, agent_cmd::agent_pending, agent_cmd::agent_decide,
            cases::create_project, cases::get_projects, cases::delete_project,
            cases::add_entry, cases::add_entries, cases::get_entries, cases::delete_entry,
            evidence_cmd::list_evidence, evidence_cmd::add_evidence, evidence_cmd::add_dropped_evidence,
            evidence_cmd::verify_evidence, evidence_cmd::export_evidence, evidence_cmd::evidence_custody,
            evidence_cmd::add_evidence_note, evidence_cmd::delete_evidence,
            toolbox::open_nmap_file, toolbox::open_dropped_nmap, toolbox::add_kb_entry, toolbox::get_kb_entries, toolbox::delete_kb_entry,
            backup_cmd::export_backup, backup_cmd::pick_backup_file, backup_cmd::import_backup,
            activity_cmd::get_activity_log, activity_cmd::get_activity_older,
            recovery::generate_recovery_codes, recovery::reset_master_password, recovery::verify_master_password,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("Encra failed to start: {error}");
        std::process::exit(1);
    }
}
