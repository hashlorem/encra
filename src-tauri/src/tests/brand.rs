//! Carrying a vault over from the Cobrypt and KeyRPT names.

use base64::Engine;
use rusqlite::Connection;
use zeroize::Zeroize;
use crate::paths::*;
use crate::vault;
use super::support::*;

#[test]
fn test_database_brand_migration_copies_and_reopens_without_removing_legacy() {
    let dir = migration_test_dir("brand-migration-success");
    let legacy = dir.join(LEGACY_VAULTS[0].1);
    let current = dir.join(CURRENT_DATABASE_NAME);
    create_marker_database(&legacy, "legacy-vault-survives");

    let migrated = migrate_database_if_needed(&current, std::slice::from_ref(&legacy)).unwrap();

    assert!(migrated);
    assert!(legacy.is_file(), "previous vault database must remain recoverable");
    assert!(current.is_file(), "Encra database must be activated atomically");
    assert_eq!(read_marker_after_reopen(&current), "legacy-vault-survives");
    assert_eq!(read_marker_after_reopen(&legacy), "legacy-vault-survives");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_database_brand_migration_never_overwrites_existing_encra_vault() {
    let dir = migration_test_dir("brand-migration-no-overwrite");
    let legacy = dir.join(LEGACY_VAULTS[0].1);
    let current = dir.join(CURRENT_DATABASE_NAME);
    create_marker_database(&legacy, "legacy-value");
    create_marker_database(&current, "current-value");

    let migrated = migrate_database_if_needed(&current, &[legacy]).unwrap();

    assert!(!migrated);
    assert_eq!(read_marker_after_reopen(&current), "current-value");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_database_brand_migration_failure_leaves_source_and_destination_unchanged() {
    let dir = migration_test_dir("brand-migration-failure");
    let legacy = dir.join(LEGACY_VAULTS[0].1);
    let current = dir.join(CURRENT_DATABASE_NAME);
    let corrupt_bytes = b"not a sqlite database";
    std::fs::write(&legacy, corrupt_bytes).unwrap();

    let result = migrate_database_if_needed(&current, std::slice::from_ref(&legacy));

    assert!(result.is_err());
    assert!(!current.exists(), "failed migration must not activate a partial database");
    assert_eq!(std::fs::read(&legacy).unwrap(), corrupt_bytes);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_brand_migration_prefers_cobrypt_over_keyrpt_and_keeps_both() {
    let (root, encra_dir) = app_data_root("brand-prefers-cobrypt");
    let cobrypt = root.join("com.cobrypt.desktop").join("cobrypt.db");
    let keyrpt = root.join("com.keyrpt.app").join("keyrpt.db");
    std::fs::create_dir_all(cobrypt.parent().unwrap()).unwrap();
    std::fs::create_dir_all(keyrpt.parent().unwrap()).unwrap();
    create_marker_database(&cobrypt, "cobrypt-vault");
    create_marker_database(&keyrpt, "keyrpt-vault");
    let cobrypt_bytes = std::fs::read(&cobrypt).unwrap();
    let keyrpt_bytes = std::fs::read(&keyrpt).unwrap();

    // The Encra data directory does not exist yet on a first launch.
    let current = encra_dir.join(CURRENT_DATABASE_NAME);
    let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

    assert!(migrated);
    assert_eq!(read_marker_after_reopen(&current), "cobrypt-vault");
    assert_eq!(std::fs::read(&cobrypt).unwrap(), cobrypt_bytes, "Cobrypt source must be untouched");
    assert_eq!(std::fs::read(&keyrpt).unwrap(), keyrpt_bytes, "KeyRPT source must be untouched");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_brand_migration_falls_back_to_keyrpt_without_cobrypt() {
    let (root, encra_dir) = app_data_root("brand-falls-back-keyrpt");
    let keyrpt = root.join("com.keyrpt.app").join("keyrpt.db");
    std::fs::create_dir_all(keyrpt.parent().unwrap()).unwrap();
    // An empty Cobrypt directory, as left behind by an uninstall.
    std::fs::create_dir_all(root.join("com.cobrypt.desktop")).unwrap();
    create_marker_database(&keyrpt, "keyrpt-vault");

    let current = encra_dir.join(CURRENT_DATABASE_NAME);
    let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

    assert!(migrated);
    assert_eq!(read_marker_after_reopen(&current), "keyrpt-vault");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_brand_migration_with_nothing_to_migrate_is_a_no_op() {
    let (root, encra_dir) = app_data_root("brand-nothing");
    let current = encra_dir.join(CURRENT_DATABASE_NAME);

    let migrated = migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap();

    assert!(!migrated);
    assert!(!current.exists(), "a fresh install must start with no vault file");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_migrated_cobrypt_vault_unlocks_with_same_password_after_reopen() {
    let (root, encra_dir) = app_data_root("brand-real-vault");
    let cobrypt = root.join("com.cobrypt.desktop").join("cobrypt.db");
    std::fs::create_dir_all(cobrypt.parent().unwrap()).unwrap();
    let password = "migration-master-password";
    let dek = create_test_vault(&cobrypt, password);
    {
        let conn = Connection::open(&cobrypt).unwrap();
        seed_vault(&conn, &dek);
    }

    let current = encra_dir.join(CURRENT_DATABASE_NAME);
    assert!(migrate_database_if_needed(&current, &legacy_database_candidates(&encra_dir)).unwrap());

    // Fresh connection to the migrated file, as the next app launch would do.
    let conn = vault::init_db(&current).unwrap();
    let config = |key: &str| -> String {
        conn.query_row("SELECT value FROM vault_config WHERE key = ?1", [key], |row| row.get(0)).unwrap()
    };
    assert!(vault::verify_password(password, &config("password_hash")).unwrap());
    assert!(!vault::verify_password("wrong-password-123", &config("password_hash")).unwrap());

    let salt = base64::engine::general_purpose::STANDARD.decode(config("kdf_salt")).unwrap();
    let mut wrapping_key = vault::derive_key(password, &salt).unwrap();
    let unwrapped = vault::unwrap_dek(&config("encrypted_dek"), &wrapping_key).unwrap();
    wrapping_key.zeroize();
    assert_eq!(unwrapped, dek, "migrated vault must yield the same data key");

    let stored_pw: String = conn
        .query_row("SELECT password_encrypted FROM credentials WHERE id = 'c1'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(vault::decrypt_to_string(&unwrapped, &stored_pw).unwrap(), "gh_p@$$w0rd");
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}
