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

#[test]
fn test_case_indicators_and_timeline_draw_on_notes_and_evidence() {
    use crate::commands::cases::{case_sources, timeline};
    use crate::indicators::{self, Kind};

    let dir = migration_test_dir("case-views");
    let path = dir.join("vault.db");
    let dek = create_test_vault(&path, "a-long-master-password");
    let conn = Connection::open(&path).unwrap();
    bring_up_to_date(&conn, "a-long-master-password", &dek).unwrap();
    crate::evidence::init_tables(&conn).unwrap();
    let seal = |table: &str, id: &str, column: &str, value: &str| crate::fields::seal(&dek, table, id, column, value).unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, description, created_at) VALUES ('case', ?1, ?2, '2026-11-03 09:12:40')",
        [seal("projects", "case", "name", "Phishing, finance mailbox"), seal("projects", "case", "description", "Wire request from a lookalike, first reported from 192.0.2.10")],
    )
    .unwrap();
    for (id, title, content, at) in [
        ("e2", "Gateway log", "One click from 10.0.4.12 to hxxps://invoices-examp1e[.]com/pay", "2026-11-03 10:02:11"),
        ("e1", "Header analysis", "Sent from 203.0.113.45 via invoices-examp1e.com, CVE-2023-23397 noted", "2026-11-03 09:31:05"),
    ] {
        conn.execute(
            "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity, created_at) VALUES (?1, 'case', ?2, ?3, 'finding', 'high', ?4)",
            [id, &seal("journal_entries", id, "title", title), &seal("journal_entries", id, "content", content), at],
        )
        .unwrap();
    }
    let evidence_dir = dir.join("evidence");
    let file = dir.join("invoice.pdf.html");
    std::fs::write(&file, b"<html>fake invoice</html>").unwrap();
    let staged = crate::evidence::stage(&evidence_dir, &file, &mut |_, _| {}).unwrap();
    let item = crate::evidence::commit(&conn, &dek, &evidence_dir, "case", staged, "").unwrap();
    crate::evidence::add_note(&conn, &dek, &item.id, "Sandbox reached 198.51.100.23").unwrap();

    let found = indicators::extract(&case_sources(&conn, &dek, &evidence_dir, "case").unwrap());
    let has = |kind: Kind, value: &str| found.iter().any(|i| i.kind == kind && i.value == value);
    assert!(has(Kind::Ipv4, "203.0.113.45") && has(Kind::Ipv4, "10.0.4.12") && has(Kind::Ipv4, "198.51.100.23"), "custody notes count");
    assert!(has(Kind::Domain, "invoices-examp1e.com") && has(Kind::Url, "https://invoices-examp1e.com/pay"));
    assert!(has(Kind::Sha256, &item.hashes.sha256) && has(Kind::Md5, &item.hashes.md5), "evidence hashes");
    assert!(has(Kind::Cve, "CVE-2023-23397"));
    let reported = found.iter().find(|i| i.value == "192.0.2.10").expect("the case's own description is searched too");
    assert_eq!(reported.sources, ["Case description"]);
    let domain = found.iter().find(|i| i.value == "invoices-examp1e.com").unwrap();
    assert_eq!(domain.sources, ["Header analysis", "Gateway log"], "oldest note first");
    assert!(!found.iter().any(|i| i.value.contains("invoice.pdf")), "the file name is not a domain");

    // Copying names an indicator by value; only this case's indicators come
    // back, so the page can't use it to put other text on the clipboard.
    use crate::commands::cases::indicator_lines;
    assert_eq!(indicator_lines(&found, true, Some("203.0.113.45")), ["203[.]0[.]113[.]45"]);
    assert_eq!(indicator_lines(&found, false, Some("203.0.113.45")), ["203.0.113.45"]);
    assert!(indicator_lines(&found, true, Some("a-long-master-password")).is_empty(), "anything else copies nothing");
    assert_eq!(indicator_lines(&found, false, None).len(), found.len(), "all of them, one per line");

    let events = timeline(&conn, &dek, &evidence_dir, "case").unwrap();
    let order: Vec<(&str, &str)> = events.iter().map(|e| (e.source, e.title.as_str())).collect();
    assert_eq!(order[..3], [("case", "Phishing, finance mailbox"), ("entry", "Header analysis"), ("entry", "Gateway log")]);
    let evidence_actions: Vec<&str> = events.iter().filter(|e| e.source == "evidence").map(|e| e.action.as_deref().unwrap()).collect();
    assert_eq!(evidence_actions, ["added", "note"]);
    assert!(events.windows(2).all(|w| w[0].at <= w[1].at));
    assert!(timeline(&conn, &dek, &evidence_dir, "missing").is_err());
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}
