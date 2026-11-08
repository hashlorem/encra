//! Cases, their notes and their evidence.

use rusqlite::Connection;
use crate::commands::{cases::*, lifecycle::*};
use crate::{evidence, journal};
use super::support::*;

#[test]
fn test_deleting_a_case_removes_its_evidence() {
    let dir = migration_test_dir("case-delete");
    let path = dir.join("vault.db");
    let dek = create_test_vault(&path, "a-long-master-password");
    let conn = Connection::open(&path).unwrap();
    seed_vault(&conn, &dek);
    bring_up_to_date(&conn, "a-long-master-password", &dek).unwrap();
    let evidence_dir = dir.join("evidence");
    let file = dir.join("dump.raw");
    std::fs::write(&file, b"memory").unwrap();
    let staged = evidence::stage(&evidence_dir, &file, &mut |_, _| {}).unwrap();
    let item = evidence::commit(&conn, &dek, &evidence_dir, "p1", staged, "").unwrap();
    assert!(evidence_dir.join(format!("{}.enc", item.id)).exists());

    let ids = delete_project_records(&conn, "p1").unwrap();
    evidence::remove_files(&evidence_dir, &ids);
    assert_eq!(ids, std::slice::from_ref(&item.id));
    assert!(!evidence_dir.join(format!("{}.enc", item.id)).exists());
    for table in ["evidence_items", "evidence_custody", "journal_entries", "projects"] {
        assert_eq!(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap(), 0, "{table}");
    }
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_bulk_entry_insert_is_atomic_on_failure() {
    // Saving a parsed scan writes many entries at once. One bad row must not
    // leave the engagement holding a subset of the hosts.
    let dir = migration_test_dir("bulk-entries-atomic");
    let path = dir.join("vault.db");
    let dek = create_test_vault(&path, "destination-password-456");

    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    conn.execute("INSERT INTO projects (id, name) VALUES ('p1', 'Engagement')", []).unwrap();

    let good = journal::EntryInput {
        project_id: "p1".into(),
        title: "host a".into(),
        content: "22/tcp open".into(),
        entry_type: "recon".into(),
        severity: "info".into(),
    };
    let bad = journal::EntryInput {
        project_id: "does-not-exist".into(),
        title: "host b".into(),
        content: "80/tcp open".into(),
        entry_type: "recon".into(),
        severity: "info".into(),
    };

    let result = insert_entries(&conn, &dek, &[good, bad]);
    assert!(result.is_err(), "a foreign key violation must fail the whole batch");

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM journal_entries", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0, "no entry may be written when the batch fails");

    std::fs::remove_dir_all(dir).unwrap();
}
