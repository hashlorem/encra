//! Logins: list, read one field at a time, copy, add, edit, delete, 2FA.

use std::sync::Arc;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::clipboard::ClipboardGuard;
use crate::credentials::{self, CopyField, CredentialDetail, CredentialSummary, TotpCode};
use crate::db::*;
use crate::util::{check_field, uuid_v4};
use crate::vault::{AppState, CredentialInput};
use crate::{activity, agent, fields, hibp, qr, totp};

/// Validate a credential's user-supplied fields before storing them.
pub(crate) fn validate_credential(input: &CredentialInput) -> Result<(), String> {
    check_field(&input.service, "service", MAX_FIELD_CHARS)?;
    check_field(&input.username, "username", MAX_FIELD_CHARS)?;
    check_field(&input.url, "url", MAX_FIELD_CHARS)?;
    check_field(&input.password, "password", MAX_LONG_FIELD_CHARS)?;
    check_field(&input.notes, "notes", MAX_LONG_FIELD_CHARS)?;
    if input.service.trim().is_empty() {
        return Err("service must not be empty".into());
    }
    Ok(())
}

// --- Impl functions (called by both commands and tests) ---

#[tauri::command]
pub(crate) fn list_credentials(state: tauri::State<AppState>) -> Result<Vec<CredentialSummary>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::list_summaries(&db, &key)
}

#[tauri::command]
pub(crate) fn get_credential(state: tauri::State<AppState>, id: String) -> Result<CredentialDetail, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::detail(&db, &key, &id)
}

/// The one path that sends a stored password to the webview: an explicit Show.
#[tauri::command]
pub(crate) fn reveal_password(state: tauri::State<AppState>, id: String) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::reveal_password(&db, &key, &id).map(|password| password.to_string())
}

#[tauri::command]
pub(crate) fn get_totp(state: tauri::State<AppState>, id: String) -> Result<Option<TotpCode>, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::totp_code(&db, &key, &id)
}

/// Copy a login field straight from the database to the clipboard.
#[tauri::command]
pub(crate) fn copy_credential_field(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    id: String,
    field: CopyField,
) -> Result<(), String> {
    let value = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        credentials::copy_value(&db, &key, &id, field)?
    };
    clipboard.copy(&value)
}

/// Copy text the webview already holds (a generated password, a command), so
/// every copy shares the same wipe.
#[tauri::command]
pub(crate) fn copy_text(
    state: tauri::State<AppState>,
    clipboard: tauri::State<Arc<ClipboardGuard>>,
    mut text: String,
) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let result = clipboard.copy(&text);
    text.zeroize();
    result
}

#[tauri::command]
pub(crate) async fn check_credential_breach(state: tauri::State<'_, AppState>, id: String) -> Result<u32, String> {
    let password = {
        let key = require_unlocked(&state)?;
        let db = require_db(&state)?;
        credentials::reveal_password(&db, &key, &id)?
    };
    if password.is_empty() {
        return Err("that login has no password".into());
    }
    let count = hibp::check_password(&password).await?;
    // Remembered, sealed, so the Vault and the check-up know it next time.
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    credentials::record_breach(&db, &key, &id, count)?;
    Ok(count)
}

#[tauri::command]
pub(crate) fn add_credential(state: tauri::State<AppState>, input: CredentialInput) -> Result<String, String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    let id = uuid_v4();
    let seal = |column: &str, value: &str| fields::seal(&key, "credentials", &id, column, value);
    let encrypted_service = seal("service", &input.service)?;
    let encrypted_pw = seal("password_encrypted", &input.password)?;
    let encrypted_user = seal("username", &input.username)?;
    let encrypted_url = seal("url", &input.url)?;
    let encrypted_notes = seal("notes", &input.notes)?;

    in_transaction(&db, || {
        db.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id, encrypted_service, encrypted_user, encrypted_pw, encrypted_url, encrypted_notes],
        ).map_err(|e| e.to_string())?;
        // No name: the log is readable while locked, so it must not list
        // which accounts the vault holds.
        activity::log_action(&db, "credential_add", "added a login");
        Ok(())
    })?;
    seal_log(&db, &key);

    // Only the new id goes back; the webview reloads the list for the rest.
    Ok(id)
}

#[tauri::command]
pub(crate) fn update_credential(state: tauri::State<AppState>, id: String, input: CredentialInput) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    validate_credential(&input)?;

    credentials::update(&db, &key, &id, &input)
}

#[tauri::command]
pub(crate) fn delete_credential(state: tauri::State<AppState>, id: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    in_transaction(&db, || {
        db.execute("DELETE FROM credentials WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
        agent::refs::forget_login(&db, &id)?;
        activity::log_action(&db, "credential_delete", "deleted a login");
        Ok(())
    })?;
    seal_log(&db, &key);
    Ok(())
}


// ===== TOTP =====

/// Seal a login's 2FA settings. Shared by every way of adding one.
pub(crate) fn store_totp(db: &Connection, key: &[u8; 32], credential_id: &str, config: &totp::Config) -> Result<(), String> {
    let encrypted = fields::seal(key, "credentials", credential_id, "totp_secret", &config.to_stored())?;
    let updated = db.execute("UPDATE credentials SET totp_secret = ?1 WHERE id = ?2", rusqlite::params![encrypted, credential_id])
        .map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("credential not found".into());
    }
    Ok(())
}

/// A setup key or an otpauth:// link, typed or pasted.
#[tauri::command]
pub(crate) fn setup_totp(state: tauri::State<AppState>, credential_id: String, secret: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let config = totp::Config::parse(&secret)?;
    let db = require_db(&state)?;
    store_totp(&db, &key, &credential_id, &config)
}

/// A screenshot of the QR on the clipboard. Async so decoding a large
/// screenshot doesn't stall the window.
#[tauri::command]
pub(crate) async fn setup_totp_from_clipboard(state: tauri::State<'_, AppState>, credential_id: String) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let config = totp::Config::parse(&qr::read_code_link(&qr::from_clipboard()?)?)?;
    let db = require_db(&state)?;
    store_totp(&db, &key, &credential_id, &config)?;
    qr::clear_clipboard();
    Ok(())
}

/// An image file the person chose, sent as raw bytes with the login's id in
/// a header.
#[tauri::command]
pub(crate) async fn setup_totp_from_image(state: tauri::State<'_, AppState>, request: tauri::ipc::Request<'_>) -> Result<(), String> {
    let key = require_unlocked(&state)?;
    let credential_id = request.headers().get("credential-id").and_then(|v| v.to_str().ok()).ok_or("missing login id")?.to_string();
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected image bytes".into());
    };
    let config = totp::Config::parse(&qr::read_code_link(&qr::from_encoded(bytes)?)?)?;
    let db = require_db(&state)?;
    store_totp(&db, &key, &credential_id, &config)
}

#[tauri::command]
pub(crate) fn remove_totp(state: tauri::State<AppState>, credential_id: String) -> Result<(), String> {
    let _key = require_unlocked(&state)?;
    let db = require_db(&state)?;
    db.execute("UPDATE credentials SET totp_secret = NULL WHERE id = ?1", rusqlite::params![credential_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ===== HIBP =====

#[tauri::command]
pub(crate) async fn check_hibp(state: tauri::State<'_, AppState>, password: String) -> Result<u32, String> {
    // This hands a plaintext password to a network client, so it must not be
    // reachable while the vault is locked.
    let _key = require_unlocked(&state)?;
    hibp::check_password(&password).await
}
