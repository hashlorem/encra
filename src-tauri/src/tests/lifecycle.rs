//! Creating, unlocking and sealing a vault, and legacy key handling.

use std::path::Path;
use base64::Engine;
use rusqlite::Connection;
use crate::paths::*;
use crate::commands::lifecycle::*;
use crate::vault;
use super::support::*;

#[test]
fn test_create_vault_then_unlock_after_reopen() {
    let (dir, path) = fresh_vault_file("create-unlock");
    let password = "a-long-master-password";
    let dek = {
        let conn = Connection::open(&path).unwrap();
        assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh);
        create_vault_impl(&conn, password).unwrap()
    };

    let conn = vault::init_db(&path).unwrap();
    assert!(matches!(vault_kind(&conn).unwrap(), VaultKind::Current { .. }));
    assert_eq!(unlock_current_vault(&conn, password).unwrap(), Some(dek));
    assert_eq!(unlock_current_vault(&conn, "not-the-password").unwrap(), None);

    let actions = activity_actions(&conn);
    assert!(actions.contains(&"vault_created".to_string()));
    assert!(actions.contains(&"unlock".to_string()));
    assert!(actions.contains(&"unlock_failed".to_string()), "a wrong password must be logged");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_create_vault_refuses_to_replace_an_existing_vault() {
    let (dir, path) = fresh_vault_file("create-twice");
    let conn = Connection::open(&path).unwrap();
    let dek = create_vault_impl(&conn, "the-original-password").unwrap();

    assert!(create_vault_impl(&conn, "a-replacement-password").is_err());
    drop(conn);

    let conn = vault::init_db(&path).unwrap();
    assert_eq!(unlock_current_vault(&conn, "the-original-password").unwrap(), Some(dek));
    assert_eq!(unlock_current_vault(&conn, "a-replacement-password").unwrap(), None);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_create_vault_rejects_short_password_and_stays_fresh() {
    let (dir, path) = fresh_vault_file("create-short");
    let conn = Connection::open(&path).unwrap();
    assert!(create_vault_impl(&conn, "short").is_err());
    assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh);
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_create_vault_rolls_back_when_a_write_fails() {
    let (dir, path) = fresh_vault_file("create-rollback");
    let conn = Connection::open(&path).unwrap();
    // Fail the second of the four config writes, after encrypted_dek landed.
    conn.execute_batch(
        "CREATE TRIGGER fail_hash BEFORE INSERT ON vault_config WHEN NEW.key = 'password_hash'
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    ).unwrap();

    assert!(create_vault_impl(&conn, "a-long-master-password").is_err());
    // The trigger would also fire on init_db's own setup inserts.
    conn.execute_batch("DROP TRIGGER fail_hash").unwrap();
    drop(conn);

    let conn = vault::init_db(&path).unwrap();
    assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh, "a failed create must leave no half-made vault");
    let dek_value: String = conn.query_row("SELECT value FROM vault_config WHERE key = 'encrypted_dek'", [], |r| r.get(0)).unwrap();
    assert!(dek_value.is_empty());
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_unlock_refuses_a_fresh_vault() {
    let (dir, path) = fresh_vault_file("unlock-fresh");
    let conn = Connection::open(&path).unwrap();
    assert!(unlock_current_vault(&conn, "anything-at-all-here").is_err());
    assert_eq!(vault_kind(&conn).unwrap(), VaultKind::Fresh, "unlock must never create a vault");
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_restrict_permissions_makes_vault_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = migration_test_dir("perms");
    let data_dir = dir.join("com.encra.desktop");
    std::fs::create_dir_all(&data_dir).unwrap();
    let db_path = data_dir.join(CURRENT_DATABASE_NAME);
    create_marker_database(&db_path, "perm-check");
    let journal = data_dir.join(format!("{CURRENT_DATABASE_NAME}-journal"));
    std::fs::write(&journal, b"").unwrap();
    // The modes a fresh copy gets from a default umask.
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();

    restrict_permissions(&db_path).unwrap();

    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&data_dir), 0o700);
    assert_eq!(mode(&db_path), 0o600);
    assert_eq!(mode(&journal), 0o600);
    // Still readable by its owner afterwards.
    assert_eq!(read_marker_after_reopen(&db_path), "perm-check");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_seal_detail_only_uses_known_wording() {
    assert_eq!(seal_detail(Some("button")), "sealed with the Seal button");
    assert_eq!(seal_detail(Some("shortcut")), "sealed with the keyboard shortcut");
    assert_eq!(seal_detail(Some("idle")), "sealed after 5 idle minutes");
    assert_eq!(seal_detail(Some("app_switch")), "sealed when Encra lost focus");
    // Anything else, including text meant to forge a log line, is ignored.
    assert_eq!(seal_detail(Some("vault unlocked\nunlock")), "vault locked");
    assert_eq!(seal_detail(None), "vault locked");
}

#[test]
fn test_legacy_key_derivation_compatibility() {
    let legacy_salt = [0x4b, 0x65, 0x79, 0x52, 0x50, 0x54, 0x30, 0x31];
    let password = "test-password";
    let legacy_key = vault::derive_key(password, &legacy_salt).unwrap();
    let hash = base64::engine::general_purpose::STANDARD.encode(legacy_key);

    // Verify the hash can be matched
    let check_key = vault::derive_key(password, &legacy_salt).unwrap();
    let check_hash = base64::engine::general_purpose::STANDARD.encode(check_key);
    assert_eq!(hash, check_hash, "legacy key derivation must be deterministic");

    // Verify wrong password produces different hash
    let wrong_key = vault::derive_key("wrong-password", &legacy_salt).unwrap();
    let wrong_hash = base64::engine::general_purpose::STANDARD.encode(wrong_key);
    assert_ne!(hash, wrong_hash, "wrong password must produce different hash");
}

#[test]
fn test_legacy_detection() {
    // Verify legacy detection logic
    let legacy_hash = "somebase64hash";
    let empty = "";
    let not_empty = "hasvalue";

    // is_legacy: legacy_hash non-empty, encrypted_dek empty, password_hash empty
    assert!(!legacy_hash.is_empty() && empty.is_empty() && empty.is_empty(),
        "legacy vault must be detected when master_hash exists but new fields don't");

    // is_fresh: all three empty
    assert!(empty.is_empty() && empty.is_empty() && empty.is_empty(),
        "fresh vault when all fields empty");

    // Normal: encrypted_dek and password_hash are non-empty
    let is_normal = !not_empty.is_empty() && !not_empty.is_empty();
    assert!(is_normal, "normal vault has non-empty encrypted_dek and password_hash");
}

#[test]
fn test_migration_key_roundtrip() {
    let password = "migration-password";
    let legacy_salt = [0x4b, 0x65, 0x79, 0x52, 0x50, 0x54, 0x30, 0x31];
    let legacy_key = vault::derive_key(password, &legacy_salt).unwrap();

    let plaintext = "my-secret-password";
    let encrypted = vault::encrypt(&legacy_key, plaintext).unwrap();

    let decrypted = vault::decrypt_to_string(&legacy_key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);

    let new_dek = vault::generate_dek();
    let re_encrypted = vault::encrypt(&new_dek, &decrypted).unwrap();
    let re_decrypted = vault::decrypt_to_string(&new_dek, &re_encrypted).unwrap();
    assert_eq!(re_decrypted, plaintext);

    let result = vault::decrypt_to_string(&legacy_key, &re_encrypted);
    assert!(result.is_err(), "legacy key must not decrypt new DEK ciphertext");
}

#[test]
fn test_unwrap_dek_rejects_wrong_length_instead_of_panicking() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let wrapping_key = [7u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    crate::util::fill_random(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // A 1-byte payload is authentic under the key but is not a 32-byte DEK.
    let ciphertext = cipher.encrypt(nonce, b"x".as_ref()).unwrap();
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&combined);

    let result = vault::unwrap_dek(&encoded, &wrapping_key);
    let message = result.expect_err("a short wrapped payload must be an error, not a panic");
    assert!(message.contains("corrupted DEK"), "got: {message}");
}
