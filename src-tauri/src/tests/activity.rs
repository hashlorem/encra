//! The activity log and its HMAC chain.

use rusqlite::Connection;
use crate::commands::lifecycle::*;
use crate::activity;
use super::support::*;

#[test]
fn test_activity_chain_detects_tampering() {
    let (dir, path, dek) = format_2_vault("v3-chain");
    let conn = Connection::open(&path).unwrap();
    bring_up_to_date(&conn, V2_PASSWORD, &dek).unwrap();
    let intact = |conn: &Connection| activity::verify_chain(conn, &dek).unwrap();
    assert!(intact(&conn).intact);
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0)).unwrap();
    assert!(count >= 4);

    // Entries written while locked wait, then seal on top of the chain.
    activity::log_action(&conn, "unlock_failed", "wrong master password");
    let status = intact(&conn);
    assert!(status.intact);
    assert_eq!(status.pending, 1);
    assert_eq!(activity::seal_pending(&conn, &dek).unwrap(), 1);
    assert_eq!(intact(&conn).pending, 0);

    let backup_copy = |label: &str| {
        let copy = dir.join(format!("{label}.db"));
        conn.execute("VACUUM INTO ?1", [copy.to_str().unwrap()]).unwrap();
        Connection::open(copy).unwrap()
    };

    // Edited detail.
    let edited = backup_copy("edited");
    edited.execute("UPDATE activity_log SET detail = 'nothing happened' WHERE seq = 2", []).unwrap();
    let status = activity::verify_chain(&edited, &dek).unwrap();
    assert!(!status.intact);
    assert_eq!(status.problem.as_deref(), Some("entry 2 was changed"));

    // A middle entry deleted.
    let gap = backup_copy("gap");
    gap.execute("DELETE FROM activity_log WHERE seq = 2", []).unwrap();
    assert!(!activity::verify_chain(&gap, &dek).unwrap().intact);

    // The newest entry cut off, then a new locked-time entry appended so the
    // numbers line up again: the head still catches it, and sealing refuses.
    let cut = backup_copy("cut");
    cut.execute("DELETE FROM activity_log WHERE seq = (SELECT MAX(seq) FROM activity_log)", []).unwrap();
    activity::log_action(&cut, "unlock", "vault unlocked");
    let status = activity::verify_chain(&cut, &dek).unwrap();
    assert!(!status.intact, "a cut-off tail must be detected");
    assert!(activity::seal_pending(&cut, &dek).is_err(), "must not seal over a broken chain");
    assert!(!activity::verify_chain(&cut, &dek).unwrap().intact, "the damage must stay visible");

    // A forged sealed entry.
    let forged = backup_copy("forged");
    forged.execute(
        "INSERT INTO activity_log (id, action, detail, seq, mac) VALUES ('x', 'unlock', 'forged', (SELECT MAX(seq) + 1 FROM activity_log), 'deadbeef')",
        [],
    ).unwrap();
    assert!(!activity::verify_chain(&forged, &dek).unwrap().intact);

    // The wrong key cannot vouch for the chain.
    assert!(!activity::verify_chain(&conn, &[1u8; 32]).unwrap().intact);
    drop((edited, gap, cut, forged, conn));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_activity_ids_do_not_collide() {
    let conn = Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();
    for i in 0..500 {
        activity::log_action(&conn, "test", &format!("entry {i}"));
    }
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0)).unwrap();
    assert_eq!(total, 500, "every audit entry must survive");
}

#[test]
fn test_activity_pages_newest_first_without_gaps_or_repeats() {
    let conn = Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();
    for i in 0..250 {
        activity::log_action(&conn, "test", &format!("entry {i}"));
    }
    let (first, more) = crate::commands::activity::page(&conn, None).unwrap();
    assert_eq!((first.len(), more), (100, true));
    assert_eq!(first[0].detail, "entry 249", "newest first");
    let (second, more) = crate::commands::activity::page(&conn, first.last().unwrap().seq).unwrap();
    assert_eq!((second.len(), more), (100, true));
    let (third, more) = crate::commands::activity::page(&conn, second.last().unwrap().seq).unwrap();
    assert_eq!((third.len(), more), (50, false));
    assert_eq!(third.last().unwrap().detail, "entry 0");

    let seqs: Vec<i64> = first.iter().chain(&second).chain(&third).map(|e| e.seq.unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] > w[1]), "strictly older on every page");
    assert_eq!(seqs.len(), 250);
}


#[test]
#[ignore = "benchmark: cargo test --release -- --ignored activity_log_scales"]
fn test_activity_log_scales_to_50k_entries() {
    use std::time::Instant;
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE vault_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)").unwrap();
    activity::init_activity_table(&conn).unwrap();
    let dek = [7u8; 32];

    let start = Instant::now();
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..50_000 {
        activity::log_action(&conn, "test", &format!("entry {i}"));
    }
    conn.execute_batch("COMMIT").unwrap();
    eprintln!("writing 50,000 entries: {:?}", start.elapsed());

    let start = Instant::now();
    activity::seal_pending(&conn, &dek).unwrap();
    eprintln!("sealing all 50,000 entries: {:?}", start.elapsed());

    let start = Instant::now();
    activity::log_action(&conn, "test", "one more");
    eprintln!("logging one entry on a 50,000-entry log: {:?}", start.elapsed());

    let start = Instant::now();
    activity::seal_pending(&conn, &dek).unwrap();
    eprintln!("sealing that one entry (verifies the whole chain): {:?}", start.elapsed());

    let start = Instant::now();
    let (page, _) = crate::commands::activity::page(&conn, Some(25_000)).unwrap();
    eprintln!("one page from the middle: {:?}", start.elapsed());
    assert_eq!(page.len(), 100);
    assert!(activity::verify_chain(&conn, &dek).unwrap().intact);
}
