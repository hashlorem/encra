//! The vault check-up and remembered breach checks, on a real vault file.

use rusqlite::Connection;

use crate::commands::lifecycle::*;
use crate::vault::CredentialInput;
use crate::{checkup, credentials, fields, vault};
use super::support::*;

fn add(conn: &Connection, dek: &[u8; 32], id: &str, service: &str, password: &str, created_at: &str) {
    let seal = |column: &str, value: &str| fields::seal(dek, "credentials", id, column, value).unwrap();
    conn.execute(
        "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, seal("service", service), seal("username", "hashlorem"), seal("password_encrypted", password), seal("url", ""), seal("notes", ""), created_at],
    )
    .unwrap();
}

fn seeded(label: &str) -> (std::path::PathBuf, std::path::PathBuf, [u8; 32]) {
    let (dir, path) = fresh_vault_file(label);
    let dek = create_vault_impl(&Connection::open(&path).unwrap(), "a-long-master-password").unwrap();
    let conn = vault::init_db(&path).unwrap();
    add(&conn, &dek, "spotify", "Spotify", "shared-Passw0rd!", "2026-10-01 10:00:00");
    add(&conn, &dek, "canva", "Canva", "shared-Passw0rd!", "2026-10-02 10:00:00");
    add(&conn, &dek, "coursera", "Coursera", "shared-Passw0rd!", "2026-10-03 10:00:00");
    add(&conn, &dek, "kali", "Kali VM", "toor", "2026-10-04 10:00:00");
    add(&conn, &dek, "proton", "Proton Mail", "a long proton passphrase here", "2024-03-02 09:00:00");
    add(&conn, &dek, "discord", "Discord", "dc-Unique-pass-77", "2026-11-01 10:00:00");
    (dir, path, dek)
}

#[test]
fn test_checkup_finds_reuse_weak_old_and_remembered_breaches() {
    let (dir, path, dek) = seeded("checkup");
    {
        let conn = vault::init_db(&path).unwrap();
        credentials::record_breach(&conn, &dek, "discord", 14_212).unwrap();
        credentials::record_breach(&conn, &dek, "proton", 0).unwrap();
    }

    let conn = vault::init_db(&path).unwrap();
    let report = checkup::run(&conn, &dek).unwrap();
    assert_eq!(report.total, 6);
    let reused: Vec<Vec<&str>> = report.reused.iter().map(|g| { let mut names: Vec<&str> = g.iter().map(|l| l.service.as_str()).collect(); names.sort(); names }).collect();
    assert_eq!(reused, [["Canva", "Coursera", "Spotify"]]);
    assert_eq!(report.weak.iter().map(|l| l.service.as_str()).collect::<Vec<_>>(), ["Kali VM"]);
    assert_eq!(report.old.len(), 1);
    assert_eq!((report.old[0].login.service.as_str(), report.old[0].since.as_str()), ("Proton Mail", "2024-03-02 09:00:00"));
    assert_eq!(report.breached.len(), 1, "a clean result is remembered but not listed");
    assert_eq!((report.breached[0].login.service.as_str(), report.breached[0].count), ("Discord", 14_212));
    assert_eq!(report.unchecked, 4);
    assert!(report.last_checked.is_some());

    // The list and the record know about the breach after reopening.
    let discord = credentials::list_summaries(&conn, &dek).unwrap().into_iter().find(|c| c.id == "discord").unwrap();
    assert!(discord.breached);
    assert_eq!(credentials::detail(&conn, &dek, "discord").unwrap().breach.unwrap().count, 14_212);

    // The report is flags and names only.
    let json = serde_json::to_string(&report).unwrap();
    for secret in ["shared-Passw0rd!", "toor", "proton passphrase", "dc-Unique-pass-77"] {
        assert!(!json.contains(secret), "{secret} leaked into the report");
    }
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_a_new_password_restarts_its_age_and_drops_the_old_breach_result() {
    let (dir, path, dek) = seeded("checkup-update");
    let conn = vault::init_db(&path).unwrap();
    credentials::record_breach(&conn, &dek, "proton", 3).unwrap();
    let edit = |password: &str, notes: &str| CredentialInput {
        service: "Proton Mail".into(),
        username: "hashlorem".into(),
        password: password.into(),
        url: String::new(),
        notes: notes.into(),
    };

    // Other edits, a blank password and the same password keep both.
    credentials::update(&conn, &dek, "proton", &edit("", "new note")).unwrap();
    credentials::update(&conn, &dek, "proton", &edit("a long proton passphrase here", "again")).unwrap();
    let detail = credentials::detail(&conn, &dek, "proton").unwrap();
    assert_eq!(detail.notes, "again");
    assert_eq!(detail.password_changed_at, "2024-03-02 09:00:00");
    assert_eq!(detail.breach.unwrap().count, 3);

    // A new password: dated today, breach result gone, no longer old.
    credentials::update(&conn, &dek, "proton", &edit("a brand new proton passphrase", "again")).unwrap();
    let detail = credentials::detail(&conn, &dek, "proton").unwrap();
    assert_ne!(detail.password_changed_at, "2024-03-02 09:00:00");
    assert!(detail.breach.is_none());
    assert_eq!(credentials::reveal_password(&conn, &dek, "proton").unwrap().as_str(), "a brand new proton passphrase");
    assert!(checkup::run(&conn, &dek).unwrap().old.is_empty());

    assert!(credentials::update(&conn, &dek, "missing", &edit("x", "")).is_err());

    // A damaged stored password can still be replaced.
    conn.execute("UPDATE credentials SET password_encrypted = 'v2:garbage' WHERE id = 'kali'", []).unwrap();
    assert!(credentials::reveal_password(&conn, &dek, "kali").is_err());
    let fixed = CredentialInput { service: "Kali VM".into(), username: "root".into(), password: "a new kali passphrase".into(), url: String::new(), notes: String::new() };
    credentials::update(&conn, &dek, "kali", &fixed).unwrap();
    assert_eq!(credentials::reveal_password(&conn, &dek, "kali").unwrap().as_str(), "a new kali passphrase");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}
