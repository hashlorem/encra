//! Logins: reads that keep secrets in Rust, copying, validation and 2FA.

use std::sync::Arc;
use rusqlite::Connection;
use crate::clipboard::ClipboardGuard;
use crate::credentials::{self, CopyField};
use crate::db::*;
use crate::commands::{lifecycle::*, logins::*};
use crate::vault::{self, CredentialInput};
use crate::{agent, clipboard, fields, totp};
use super::support::*;

#[test]
fn test_credential_list_carries_no_secrets() {
    let (dir, conn, dek) = reopened_seeded_vault("cred-list");

    let list = credentials::list_summaries(&conn, &dek).unwrap();
    let json = serde_json::to_string(&list).unwrap();

    assert_eq!(list.len(), 2);
    for secret in ["gh_p@$$w0rd", "short12chars", "personal account", "JBSWY3DPEHPK3PXP", "https://github.com", "prod"] {
        assert!(!json.contains(secret), "list must not carry {secret:?}: {json}");
    }
    let github = list.iter().find(|c| c.id == "c1").unwrap();
    assert_eq!(github.username, "dev@example.com");
    assert!(github.has_totp);
    assert!(!list.iter().find(|c| c.id == "c2").unwrap().has_totp);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_credential_detail_reveal_and_copy_values() {
    let (dir, conn, dek) = reopened_seeded_vault("cred-fields");

    let detail = credentials::detail(&conn, &dek, "c1").unwrap();
    assert_eq!(detail.url, "https://github.com");
    assert_eq!(detail.notes, "personal account");
    assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");

    let copy = |field| credentials::copy_value(&conn, &dek, "c1", field).unwrap().to_string();
    assert_eq!(copy(CopyField::Username), "dev@example.com");
    assert_eq!(copy(CopyField::Password), "gh_p@$$w0rd");
    assert_eq!(copy(CopyField::Url), "https://github.com");
    let code = credentials::totp_code(&conn, &dek, "c1").unwrap().unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.code.chars().all(|c| c.is_ascii_digit()));
    assert!((1..=30).contains(&code.remaining));

    assert_eq!(credentials::totp_code(&conn, &dek, "c2").unwrap(), None);
    assert!(credentials::copy_value(&conn, &dek, "c2", CopyField::Totp).is_err());
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_credential_reads_fail_cleanly_on_bad_input() {
    let (dir, conn, dek) = reopened_seeded_vault("cred-bad-input");

    // Unknown id: an error, not an empty value.
    assert!(credentials::detail(&conn, &dek, "missing").is_err());
    assert!(credentials::reveal_password(&conn, &dek, "missing").is_err());
    assert!(credentials::copy_value(&conn, &dek, "missing", CopyField::Password).is_err());

    // Wrong key: the password is an error, never placeholder text that could
    // be copied as if it were real; the list still loads with blank usernames.
    let wrong = [7u8; 32];
    let err = credentials::reveal_password(&conn, &wrong, "c1").unwrap_err();
    assert!(!err.contains("[decryption failed]"));
    let list = credentials::list_summaries(&conn, &wrong).unwrap();
    assert!(list.iter().all(|c| c.username.is_empty()));

    // Corrupted ciphertext on disk: errors, no panic.
    conn.execute("UPDATE credentials SET password_encrypted = 'not base64 at all!', totp_secret = 'AAAA' WHERE id = 'c1'", []).unwrap();
    assert!(credentials::reveal_password(&conn, &dek, "c1").is_err());
    assert!(credentials::totp_code(&conn, &dek, "c1").is_err());
    assert!(credentials::copy_value(&conn, &dek, "c1", CopyField::Password).is_err());
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_copy_credential_field_reaches_the_clipboard_and_lock_wipes_it() {
    use clipboard::tests::FakeClipboard;
    let (dir, conn, dek) = reopened_seeded_vault("cred-copy");
    let fake = Arc::new(FakeClipboard::default());
    let guard = ClipboardGuard::new(Box::new(Arc::clone(&fake)), std::time::Duration::from_secs(60));

    let value = credentials::copy_value(&conn, &dek, "c1", CopyField::Password).unwrap();
    guard.copy(&value).unwrap();
    assert_eq!(fake.0.lock().unwrap().as_deref(), Some("gh_p@$$w0rd"));

    assert!(guard.wipe_now(), "locking must wipe a pending copy");
    assert_eq!(*fake.0.lock().unwrap(), None);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_credential_detail_says_whether_a_password_exists_and_nothing_more() {
    let (dir, conn, dek) = reopened_seeded_vault("cred-has-password");
    assert!(credentials::detail(&conn, &dek, "c1").unwrap().has_password);
    let empty = fields::seal(&dek, "credentials", "c1", "password_encrypted", "").unwrap();
    conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&empty]).unwrap();
    assert!(!credentials::detail(&conn, &dek, "c1").unwrap().has_password);
    let json = serde_json::to_string(&credentials::detail(&conn, &dek, "c2").unwrap()).unwrap();
    assert!(!json.contains("length") && !json.contains("short12chars"));
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_input_validation_rejects_weak_and_oversized_values() {
    assert!(reject_empty_password("", "Password").is_err());
    assert!(require_min_length("too-short", "Password", MIN_MASTER_PASSWORD_CHARS).is_err());
    assert!(require_min_length("long-enough-password", "Password", MIN_MASTER_PASSWORD_CHARS).is_ok());

    let blank_service = CredentialInput {
        service: "   ".into(), username: String::new(), password: String::new(),
        url: String::new(), notes: String::new(),
    };
    assert!(validate_credential(&blank_service).is_err(), "blank service must be rejected");

    let oversized = CredentialInput {
        service: "a".repeat(MAX_FIELD_CHARS + 1), username: String::new(),
        password: String::new(), url: String::new(), notes: String::new(),
    };
    assert!(validate_credential(&oversized).is_err(), "oversized field must be rejected");

    let valid = CredentialInput {
        service: "github.com".into(), username: "user".into(), password: "pw".into(),
        url: String::new(), notes: String::new(),
    };
    assert!(validate_credential(&valid).is_ok());
}

#[test]
fn test_totp_secret_validation() {
    assert!(totp::validate_secret("").is_err(), "empty secret must be rejected");
    assert!(totp::validate_secret("JBSWY3").is_err(), "a short secret must be rejected");
    assert!(totp::validate_secret("JBSWY3DPEHPK3PXP").is_ok(), "a 16-char base32 secret (80 bits) is acceptable");
    assert!(totp::validate_secret("JBSWY3DPEHPK3PX").is_err(), "a 15-char secret is below the 80-bit floor");
    assert!(totp::validate_secret("JBSWY3DPEHPK3PXP@").is_err(), "invalid characters must be rejected");
    assert!(totp::current("").is_err(), "an empty secret must not produce a code");
}

#[test]
fn test_totp_settings_survive_reopen_and_reach_agents() {
    let (dir, path) = fresh_vault_file("totp-settings");
    let dek = create_vault_impl(&Connection::open(&path).unwrap(), "a-long-master-password").unwrap();
    {
        let conn = vault::init_db(&path).unwrap();
        let service = fields::seal(&dek, "credentials", "t1", "service", "Example").unwrap();
        let password = fields::seal(&dek, "credentials", "t1", "password_encrypted", "pw").unwrap();
        conn.execute("INSERT INTO credentials (id, service, username, password_encrypted) VALUES ('t1', ?1, '', ?2)", [&service, &password]).unwrap();
        let link = totp::Config::parse("otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60").unwrap();
        store_totp(&conn, &dek, "t1", &link).unwrap();
        assert!(store_totp(&conn, &dek, "missing", &link).is_err(), "an unknown login is refused");
    }

    let conn = vault::init_db(&path).unwrap();
    agent::refs::init_alias_table(&conn).unwrap();
    let code = credentials::totp_code(&conn, &dek, "t1").unwrap().unwrap();
    assert_eq!((code.code.len(), code.period), (8, 60), "settings came back after reopening");
    assert!((1..=60).contains(&code.remaining));
    let (_, value) = agent::refs::resolve(&conn, &dek, "encra://Example#totp", None).unwrap();
    assert_eq!(value.len(), 8, "agents get the same kind of code");

    // Default settings are stored as the bare key, the shape older vaults
    // and backups already hold.
    store_totp(&conn, &dek, "t1", &totp::Config::parse("jbsw y3dp ehpk 3pxp").unwrap()).unwrap();
    let stored: String = conn.query_row("SELECT totp_secret FROM credentials WHERE id = 't1'", [], |r| r.get(0)).unwrap();
    assert_eq!(fields::open_to_string(&dek, "credentials", "t1", "totp_secret", &stored).unwrap(), "JBSWY3DPEHPK3PXP");
    assert_eq!(credentials::totp_code(&conn, &dek, "t1").unwrap().unwrap().period, 30);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}
