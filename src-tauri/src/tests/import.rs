//! Importing another password manager's export into a real vault file.

use rusqlite::Connection;

use crate::commands::lifecycle::*;
use crate::{credentials, fields, import, vault};
use super::support::*;

const EXPORT: &str = "Title,URL,Username,Password,Notes,OTPAuth\n\
GitHub,https://github.com,hashlorem,gh-pass,personal,otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&period=60\n\
Discord,https://discord.com,hashlorem,dc-pass,,\n\
Discord,https://discord.com,hashlorem,dc-pass,,\n\
Canva,https://canva.com,me@example.com,cv-pass,,\n";

fn vault_with_github(label: &str) -> (std::path::PathBuf, std::path::PathBuf, [u8; 32]) {
    let (dir, path) = fresh_vault_file(label);
    let dek = create_vault_impl(&Connection::open(&path).unwrap(), "a-long-master-password").unwrap();
    let conn = vault::init_db(&path).unwrap();
    let seal = |column: &str, value: &str| fields::seal(&dek, "credentials", "existing", column, value).unwrap();
    conn.execute(
        "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES ('existing', ?1, ?2, ?3, ?4, ?5)",
        [seal("service", "github"), seal("username", "hashlorem"), seal("password_encrypted", "gh-pass"), seal("url", ""), seal("notes", "")],
    )
    .unwrap();
    (dir, path, dek)
}

#[test]
fn test_import_adds_new_logins_skips_duplicates_and_survives_reopen() {
    let (dir, path, dek) = vault_with_github("import-ok");
    {
        let conn = vault::init_db(&path).unwrap();
        let mut parsed = import::parse(EXPORT).unwrap();
        import::drop_duplicates(&conn, &dek, &mut parsed).unwrap();
        // GitHub is already in the vault (names match whatever the case);
        // the second Discord row repeats the first.
        assert_eq!(parsed.skipped.duplicate, 2);
        assert_eq!(import::commit(&conn, &dek, &parsed.logins).unwrap(), 2);
    }

    let conn = vault::init_db(&path).unwrap();
    let mut logins = credentials::list_summaries(&conn, &dek).unwrap();
    logins.sort_by(|a, b| a.service.cmp(&b.service));
    let names: Vec<&str> = logins.iter().map(|l| l.service.as_str()).collect();
    assert_eq!(names, ["Canva", "Discord", "github"]);
    let canva = &logins[0];
    assert_eq!(canva.username, "me@example.com");
    assert_eq!(credentials::reveal_password(&conn, &dek, &canva.id).unwrap().as_str(), "cv-pass");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_imported_2fa_keeps_its_settings() {
    let (dir, path, dek) = vault_with_github("import-2fa");
    let conn = vault::init_db(&path).unwrap();
    // A different GitHub account, so it isn't a duplicate.
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,work-account,w-pass,,otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&period=60&digits=8\n";
    let mut parsed = import::parse(csv).unwrap();
    import::drop_duplicates(&conn, &dek, &mut parsed).unwrap();
    import::commit(&conn, &dek, &parsed.logins).unwrap();
    let id = credentials::list_summaries(&conn, &dek).unwrap().into_iter().find(|l| l.username == "work-account").unwrap().id;
    let code = credentials::totp_code(&conn, &dek, &id).unwrap().unwrap();
    assert_eq!((code.code.len(), code.period), (8, 60));
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_import_is_all_or_nothing() {
    let (dir, path, dek) = vault_with_github("import-rollback");
    let conn = vault::init_db(&path).unwrap();
    let parsed = import::parse(EXPORT).unwrap();
    // The third insert fails: nothing from the file may stay.
    conn.execute_batch(
        "CREATE TRIGGER fail_third BEFORE INSERT ON credentials WHEN (SELECT COUNT(*) FROM credentials) >= 3
         BEGIN SELECT RAISE(ABORT, 'forced'); END;",
    )
    .unwrap();
    assert!(import::commit(&conn, &dek, &parsed.logins).is_err());
    conn.execute_batch("DROP TRIGGER fail_third").unwrap();
    assert_eq!(credentials::list_summaries(&conn, &dek).unwrap().len(), 1, "only the login that was there before");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}
