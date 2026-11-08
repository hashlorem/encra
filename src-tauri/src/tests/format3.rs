//! Vault format 3: bound values, stored Argon2 settings, field encryption.

use base64::Engine;
use rusqlite::Connection;
use crate::credentials::{self};
use crate::commands::lifecycle::*;
use crate::vault;
use crate::{activity, fields, journal, kb, migrate};
use super::support::*;

#[test]
fn test_format_3_migration_binds_everything_and_survives_reopen() {
    let (dir, path, dek) = format_2_vault("v3-migrate");
    {
        let conn = Connection::open(&path).unwrap();
        assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
    }

    let conn = vault::init_db(&path).unwrap();
    assert_eq!(migrate::schema_version(&conn).unwrap(), "3");
    assert_eq!(migrate::stored_kdf_params(&conn).unwrap(), vault::KdfParams::CURRENT);

    // Every encrypted column is bound now, names included.
    for (table, columns) in fields::ALL {
        for column in *columns {
            let mut stmt = conn.prepare(&format!("SELECT {column} FROM {table}")).unwrap();
            let values: Vec<Option<String>> = stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
            for value in values.into_iter().flatten() {
                assert!(value.is_empty() || vault::is_bound(&value), "{table}.{column} not bound: {value}");
            }
        }
    }
    assert!(!raw(&conn, "SELECT group_concat(service) FROM credentials").contains("github"), "service names must be encrypted");
    assert!(!raw(&conn, "SELECT group_concat(name) FROM projects").contains("Home Lab"), "case names must be encrypted");

    // Same password, same key, after the re-wrap and a reopen.
    assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
    let list = credentials::list_summaries(&conn, &dek).unwrap();
    assert_eq!(list.iter().map(|c| c.service.as_str()).collect::<Vec<_>>(), ["aws", "github.com"], "sorted in Rust");

    // The log no longer names the login, says what happened, and is sealed.
    let details = raw(&conn, "SELECT group_concat(detail, '|') FROM activity_log");
    assert!(!details.contains("github"), "old log entries must be scrubbed: {details}");
    assert!(details.contains("login names removed from 1 older log entries"));
    let chain = activity::verify_chain(&conn, &dek).unwrap();
    assert!(chain.intact, "{:?}", chain.problem);
    assert_eq!(chain.pending, 0);

    // The safety copy is the untouched format-2 vault.
    let snapshot = Connection::open(format!("{}.pre-v3", path.display())).unwrap();
    assert_eq!(migrate::schema_version(&snapshot).unwrap(), "2");
    assert!(raw(&snapshot, "SELECT group_concat(service) FROM credentials").contains("github.com"));
    drop(snapshot);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_format_3_migration_rolls_back_and_can_retry() {
    let (dir, path, dek) = format_2_vault("v3-rollback");
    {
        let conn = Connection::open(&path).unwrap();
        // Fail on the last table, after credentials and projects were rewritten.
        conn.execute_batch(
            "CREATE TRIGGER fail_kb BEFORE UPDATE ON kb_entries BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        ).unwrap();
        assert!(bring_up_to_date(&conn, V2_PASSWORD, &dek).is_err());
        conn.execute_batch("DROP TRIGGER fail_kb").unwrap();
    }

    {
        let conn = vault::init_db(&path).unwrap();
        assert_eq!(migrate::schema_version(&conn).unwrap(), "2", "a failed migration must leave format 2");
        assert_eq!(raw(&conn, "SELECT service FROM credentials WHERE id = 'c1'"), "github.com");
        let stored = raw(&conn, "SELECT password_encrypted FROM credentials WHERE id = 'c1'");
        assert!(!vault::is_bound(&stored));
        assert_eq!(vault::decrypt_to_string(&dek, &stored).unwrap(), "gh_p@$$w0rd");
        assert!(raw(&conn, "SELECT group_concat(detail) FROM activity_log").contains("github.com"), "the scrub must roll back too");
    }

    // The next unlock simply tries again.
    let conn = Connection::open(&path).unwrap();
    assert_eq!(unlock_current_vault(&conn, V2_PASSWORD).unwrap(), Some(dek));
    assert_eq!(migrate::schema_version(&conn).unwrap(), "3");
    assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_bound_values_cannot_be_moved_or_downgraded() {
    let (dir, path, dek) = format_2_vault("v3-binding");
    let conn = Connection::open(&path).unwrap();
    bring_up_to_date(&conn, V2_PASSWORD, &dek).unwrap();
    let c1_password = raw(&conn, "SELECT password_encrypted FROM credentials WHERE id = 'c1'");
    let c1_notes = raw(&conn, "SELECT notes FROM credentials WHERE id = 'c1'");

    // Another row's password pasted in: refused.
    conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c2'", [&c1_password]).unwrap();
    assert!(credentials::reveal_password(&conn, &dek, "c2").is_err());

    // The same row's notes pasted into its password: refused.
    conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&c1_notes]).unwrap();
    assert!(credentials::reveal_password(&conn, &dek, "c1").is_err());

    // An old unbound value under the same key (from an older copy): refused.
    let unbound = vault::encrypt(&dek, "old-password").unwrap();
    conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&unbound]).unwrap();
    assert!(credentials::reveal_password(&conn, &dek, "c1").is_err(), "format-2 values must not be read once a vault is format 3");

    // Putting the real value back works again.
    conn.execute("UPDATE credentials SET password_encrypted = ?1 WHERE id = 'c1'", [&c1_password]).unwrap();
    assert_eq!(credentials::reveal_password(&conn, &dek, "c1").unwrap().as_str(), "gh_p@$$w0rd");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_kdf_params_parse_and_compatibility() {
    let current = vault::KdfParams::parse(&vault::KdfParams::CURRENT.encode()).unwrap();
    assert_eq!(current, vault::KdfParams::CURRENT);
    for hostile in ["m=99999999,t=3,p=1", "m=262144,t=0,p=1", "m=262144,t=99,p=1", "m=262144,t=3,p=64", "m=4,t=3,p=1", "m=abc,t=3,p=1", "x=1", ""] {
        assert!(vault::KdfParams::parse(hostile).is_err(), "should reject {hostile:?}");
    }
    assert!(vault::KdfParams::LEGACY.weaker_than(&vault::KdfParams::CURRENT));
    assert!(!vault::KdfParams::CURRENT.weaker_than(&vault::KdfParams::CURRENT));

    // derive_key is still the library default, so older vaults and backups open.
    let salt = [9u8; 32];
    let default = {
        let mut out = [0u8; 32];
        argon2::Argon2::default().hash_password_into(b"pw-123456789", &salt, &mut out).unwrap();
        out
    };
    assert_eq!(vault::derive_key("pw-123456789", &salt).unwrap(), default);

    // Verification reads its settings from the hash, old or new.
    let old_hash = vault::hash_password_with("pw-123456789", vault::KdfParams::LEGACY).unwrap();
    let new_hash = vault::hash_password("pw-123456789").unwrap();
    assert!(new_hash.contains("m=262144,t=3,p=1"));
    assert!(vault::verify_password("pw-123456789", &old_hash).unwrap());
    assert!(vault::verify_password("pw-123456789", &new_hash).unwrap());
    assert!(!vault::verify_password("wrong-password", &new_hash).unwrap());
}

#[test]
fn test_end_to_end_field_encryption() {
    let dir = std::env::temp_dir();
    let path = dir.join("encra-test-e2e.db");
    let _ = std::fs::remove_file(&path);

    let test_pw = "test-password";
    let kdf_salt = b"test-salt-32-bytes-long!!!!!!"; // 32 bytes

    // 1. Create vault: setup tables, generate DEK, wrap it
    let dek = vault::generate_dek();
    let wrapping_key = vault::derive_key(test_pw, kdf_salt).unwrap();
    let wrapped = vault::wrap_dek(&dek, &wrapping_key).unwrap();
    let pass_hash = vault::hash_password(test_pw).unwrap();
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(kdf_salt);

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        vault::init_db(&path).unwrap();
        journal::init_journal_tables(&conn).unwrap();
        kb::init_kb_tables(&conn).unwrap();
        activity::init_activity_table(&conn).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").ok();

        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).unwrap();
    }

    // Helper: encrypt a field
    let enc = |v: &str| vault::encrypt(&dek, v).unwrap();

    // 2. Insert test data directly
    {
        let conn = rusqlite::Connection::open(&path).unwrap();

        // Short password cred
        conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["id1", "github.com", enc("dev@example.com"), enc("gh_p@$$w0rd"), enc("https://github.com"), enc("personal GitHub account")]).unwrap();

        // Long password + multiline notes
        conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["id2", "aws-prod", enc("admin@corp.io"), enc("Xy9#mK!pW2$vL5nR8@jF3*qT7^bN1"), enc("https://aws.amazon.com"), enc("production AWS root — DO NOT SHARE\nrotated quarterly")]).unwrap();

        // TOTP entry
        conn.execute("INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params!["id3", "gitlab.com", enc("ci-bot"), enc("gl-token-2024"), enc("https://gitlab.com"), enc(""), enc("JBSWY3DPEHPK3PXP")]).unwrap();

        // Project
        conn.execute("INSERT INTO projects (id, name, description, target, methodology) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params!["p1", "Home Lab Recon", enc("Initial passive reconnaissance of internal lab network."), enc("192.168.1.0/24"), enc("OSSTMM v3 — information gathering phase")]).unwrap();

        // Journal entry
        conn.execute("INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["e1", "p1", enc("Nmap scan: open ports discovered"), enc("Found port 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL) open.\nMySQL 5.7 — check CVE-2023-XXXX."), "recon", "medium"]).unwrap();

        // KB entry
        conn.execute("INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["k1", enc("Python reverse shell"), enc("python3 -c 'import socket,subprocess,os;...'"), enc("Standard Python reverse shell for Linux/macOS."), enc("reverse-shell,python,linux"), "exploitation"]).unwrap();
    }

    // 3. Re-open DB — verify decrypted data is correct
    {
        let conn = rusqlite::Connection::open(&path).unwrap();

        let creds: Vec<(String, String, String, String, String)> = conn
            .prepare("SELECT service, username, password_encrypted, url, notes FROM credentials ORDER BY service").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap()
            .collect::<Result<Vec<_>,_>>().unwrap();

        let dec = |v: &str| vault::decrypt_to_string(&dek, v).unwrap();

        assert_eq!(creds.len(), 3);
        let gh = creds.iter().find(|c| c.0 == "github.com").unwrap();
        assert_eq!(dec(&gh.1), "dev@example.com");
        assert_eq!(dec(&gh.2), "gh_p@$$w0rd");
        assert_eq!(dec(&gh.3), "https://github.com");
        assert_eq!(dec(&gh.4), "personal GitHub account");

        let aws = creds.iter().find(|c| c.0 == "aws-prod").unwrap();
        assert_eq!(dec(&aws.2), "Xy9#mK!pW2$vL5nR8@jF3*qT7^bN1");
        assert!(dec(&aws.4).contains("DO NOT SHARE"));

        let _gl = creds.iter().find(|c| c.0 == "gitlab.com").unwrap();
        let totp_secret: String = conn.query_row(
            "SELECT totp_secret FROM credentials WHERE service='gitlab.com'", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(dec(&totp_secret), "JBSWY3DPEHPK3PXP");

        let proj: (String, String, String) = conn.query_row(
            "SELECT description, target, methodology FROM projects WHERE name='Home Lab Recon'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        ).unwrap();
        assert!(dec(&proj.0).contains("passive reconnaissance"));
        assert_eq!(dec(&proj.1), "192.168.1.0/24");
        assert!(dec(&proj.2).contains("OSSTMM"));

        let entry: (String, String) = conn.query_row(
            "SELECT title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))
        ).unwrap();
        assert!(dec(&entry.0).contains("Nmap scan"));
        assert!(dec(&entry.1).contains("CVE-2023"));

        let kb: (String, String, String, String) = conn.query_row(
            "SELECT title, command, description, tags FROM kb_entries LIMIT 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        ).unwrap();
        assert!(dec(&kb.0).contains("Python reverse shell"));
        assert!(dec(&kb.1).contains("socket"));
        assert!(dec(&kb.3).contains("reverse-shell"));
    }

    // 4. Direct SQLite — prove fields are CIPHERTEXT (base64, not readable)
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let is_b64 = |s: &str| s.len() > 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

        let u: String = conn.query_row("SELECT username FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
        assert!(is_b64(&u), "username must be encrypted base64: {}", &u[..30.min(u.len())]);

        let u2: String = conn.query_row("SELECT url FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
        assert!(is_b64(&u2), "url must be encrypted: {}", &u2[..30.min(u2.len())]);

        let n: String = conn.query_row("SELECT notes FROM credentials WHERE service='github.com'", [], |r| r.get(0)).unwrap();
        assert!(is_b64(&n), "notes must be encrypted");

        let p: (String, String, String) = conn.query_row("SELECT description, target, methodology FROM projects LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert!(is_b64(&p.0) && is_b64(&p.1) && is_b64(&p.2), "project fields must be encrypted");

        let e: (String, String) = conn.query_row("SELECT title, content FROM journal_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert!(is_b64(&e.0) && is_b64(&e.1), "journal fields must be encrypted");

        let k: (String, String, String, String) = conn.query_row("SELECT title, command, description, tags FROM kb_entries LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert!(is_b64(&k.0) && is_b64(&k.1) && is_b64(&k.2) && is_b64(&k.3), "KB fields must be encrypted");

        // Metadata plaintext
        assert_eq!(conn.query_row("SELECT service FROM credentials LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "github.com");
        assert_eq!(conn.query_row("SELECT name FROM projects LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "Home Lab Recon");
        assert_eq!(conn.query_row("SELECT entry_type FROM journal_entries LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "recon");
        assert_eq!(conn.query_row("SELECT category FROM kb_entries LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "exploitation");
    }

    std::fs::remove_file(&path).ok();
}
