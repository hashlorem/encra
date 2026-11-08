//! Recovery codes and resetting the master password.

use base64::Engine;
use crate::paths::*;
use crate::commands::lifecycle::*;
use crate::vault;
use crate::{activity, migrate};
use super::support::*;

#[test]
fn test_recovery_code_roundtrip() {
    // Generate recovery codes, recover DEK, verify
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();

    let original_dek = vault::generate_dek();
    let mut codes = activity::generate_recovery_codes(&conn, &original_dek).unwrap();
    assert_eq!(codes.len(), 8, "must generate 8 recovery codes");

    // Recover with first code
    let code = codes.remove(0);
    let recovered = activity::recover_dek(&conn, &code).unwrap();
    assert!(recovered.is_some(), "valid code must recover DEK");
    let (recovered_dek, _row_id) = recovered.unwrap();
    assert_eq!(recovered_dek, original_dek, "recovered DEK must match original");

    // Code cannot be reused (row still present, but we simulate by calling again)
    // Note: row is NOT deleted by recover_dek — the caller must delete it.
    // For this test, manually verify the row still exists.
    let still_there: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM recovery_codes",
        [], |row| row.get(0)
    ).unwrap();
    assert!(still_there, "code row must still exist after recover_dek (caller deletes it)");

    // Now manually delete to simulate the caller's transaction commit
    conn.execute("DELETE FROM recovery_codes WHERE id = ?1", rusqlite::params![_row_id]).unwrap();

    // After deletion, code should not be found
    let reused = activity::recover_dek(&conn, &code).unwrap();
    assert!(reused.is_none(), "code must not work after row deleted");
}

#[test]
fn test_recovery_code_accepts_how_people_write_it_down() {
    let dir = migration_test_dir("recovery-written");
    let path = dir.join(CURRENT_DATABASE_NAME);
    let dek = create_test_vault(&path, "original-password-123");
    let conn = vault::init_db(&path).unwrap();
    activity::init_activity_table(&conn).unwrap();
    let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();

    // Every generated code is already in normal form.
    for code in &codes {
        assert_eq!(&activity::normalize_recovery_code(code), code);
    }

    // Grouped in fours, lowercase, with a stray dash and trailing newline.
    let code = &codes[0];
    let written: String = code
        .to_lowercase()
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
        .replacen(' ', "-", 1)
        + "\n";
    let recovered = activity::recover_and_reset(&conn, &written, "a-brand-new-password").unwrap();
    assert_eq!(recovered, Some(dek));
    drop(conn);

    // After reopening: the new password works, and the code is spent.
    let conn = vault::init_db(&path).unwrap();
    assert_eq!(unlock_current_vault(&conn, "a-brand-new-password").unwrap(), Some(dek));
    assert!(activity::recover_dek(&conn, code).unwrap().is_none(), "the code must be consumed");
    // A near miss still fails: one character changed.
    let mut near = codes[1].clone();
    let last = if near.ends_with('A') { 'B' } else { 'A' };
    near.pop();
    near.push(last);
    assert!(activity::recover_dek(&conn, &near).unwrap().is_none());
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_recovery_code_wrong_code_fails() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();

    let dek = vault::generate_dek();
    activity::generate_recovery_codes(&conn, &dek).unwrap();

    let result = activity::recover_dek(&conn, "WRONG-CODE-12345").unwrap();
    assert!(result.is_none(), "wrong code must return None");
}

#[test]
fn test_recovery_code_full_reset_flow() {
    // File-backed DB to prove data survives close/reopen
    let dir = std::env::temp_dir();
    let path = dir.join("encra-test-reset.db");
    let _ = std::fs::remove_file(&path); // clean from previous runs

    let old_password = "original-password";
    let new_password = "new-password";
    let test_service = "test-service";
    let test_cred = "test-cred-password";

    // Create vault
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        activity::init_activity_table(&conn).unwrap();
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('encrypted_dek', '');
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('password_hash', '');
            INSERT OR IGNORE INTO vault_config (key, value) VALUES ('kdf_salt', '');
            CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, service TEXT, username TEXT, password_encrypted TEXT, url TEXT, notes TEXT, totp_secret TEXT, created_at TEXT);
        ").unwrap();

        let dek = vault::generate_dek();
        let salt = [0u8; 32];
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
        let wrap_key = vault::derive_key(old_password, &salt).unwrap();
        let wrapped = vault::wrap_dek(&dek, &wrap_key).unwrap();
        let pass_hash = vault::hash_password(old_password).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
        conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();

        let enc = vault::encrypt(&dek, test_cred).unwrap();
        conn.execute("INSERT INTO credentials (id, service, username, password_encrypted) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["id1", test_service, "user", enc]).unwrap();

        let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();
        // Store the code so we can use it after closing
        std::fs::write(format!("{}.code", path.display()), &codes[0]).unwrap();
    }

    // Locked: recover and reset through the single production transaction
    let recovery_code = std::fs::read_to_string(format!("{}.code", path.display())).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let dek = activity::recover_and_reset(&conn, &recovery_code, new_password)
            .unwrap()
            .expect("recovery must succeed");
        assert_eq!(dek.len(), 32, "recovery must yield a 32-byte DEK");

        // A second attempt with the same one-time code must find nothing:
        // the code was consumed in the same transaction that re-keyed the
        // vault, so it can never be spent twice.
        let again = activity::recover_and_reset(&conn, &recovery_code, "another-password").unwrap();
        assert!(again.is_none(), "recovery code must only work once");
    }

    // CLOSE and REOPEN — verify data survived
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let enc_dek: String = conn.query_row("SELECT value FROM vault_config WHERE key='encrypted_dek'", [], |r| r.get(0)).unwrap();
        let salt_b64: String = conn.query_row("SELECT value FROM vault_config WHERE key='kdf_salt'", [], |r| r.get(0)).unwrap();
        let salt = base64::engine::general_purpose::STANDARD.decode(&salt_b64).unwrap();
        let params = migrate::stored_kdf_params(&conn).unwrap();
        assert_eq!(params, vault::KdfParams::CURRENT, "a reset must store the current settings");
        let wrap_key = vault::derive_key_with(new_password, &salt, params).unwrap();
        let final_dek = vault::unwrap_dek(&enc_dek, &wrap_key).unwrap();

        let enc: String = conn.query_row("SELECT password_encrypted FROM credentials WHERE id='id1'", [], |r| r.get(0)).unwrap();
        let dec = vault::decrypt_to_string(&final_dek, &enc).unwrap();
        assert_eq!(dec, test_cred, "new password must decrypt after reopen");

        // Old password must fail
        let old_salt = [0u8; 32];
        let old_wrap = vault::derive_key(old_password, &old_salt).unwrap();
        assert!(vault::unwrap_dek(&enc_dek, &old_wrap).is_err(), "old password must not work");
    }

    // Code cannot be reused
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        assert!(activity::recover_dek(&conn, &recovery_code).unwrap().is_none(), "code must be consumed");
    }

    // Cleanup
    std::fs::remove_file(format!("{}.code", path.display())).ok();
}

#[test]
fn test_recovery_reset_rollback_on_failure() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS vault_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('encrypted_dek', '');
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('password_hash', '');
        INSERT OR IGNORE INTO vault_config (key, value) VALUES ('kdf_salt', '');
    ").unwrap();

    let old_password = "original-pw";
    let new_password = "new-pw";

    let dek = vault::generate_dek();
    let salt = [0u8; 32];
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let wrap_key = vault::derive_key(old_password, &salt).unwrap();
    let wrapped = vault::wrap_dek(&dek, &wrap_key).unwrap();
    let pass_hash = vault::hash_password(old_password).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();

    let codes = activity::generate_recovery_codes(&conn, &dek).unwrap();
    let code = &codes[0];

    // Force the reset to fail part-way through: rename vault_config so the
    // writes inside the transaction cannot land.
    conn.execute("ALTER TABLE vault_config RENAME TO vault_config_hidden", []).unwrap();

    let result = activity::recover_and_reset(&conn, code, new_password);
    assert!(result.is_err(), "reset must fail when vault_config is missing");

    // Restore table and verify the code was NOT consumed
    conn.execute("ALTER TABLE vault_config_hidden RENAME TO vault_config", []).unwrap();
    let still_exists = activity::recover_dek(&conn, code).unwrap();
    assert!(still_exists.is_some(), "recovery code must still exist after a failed reset");

    // Verify old password still unlocks
    let enc_dek: String = conn.query_row("SELECT value FROM vault_config WHERE key='encrypted_dek'", [], |r| r.get(0)).unwrap();
    let old_wrap_key = vault::derive_key(old_password, &salt).unwrap();
    let old_dek = vault::unwrap_dek(&enc_dek, &old_wrap_key).unwrap();
    assert_eq!(old_dek, dek, "DEK must be unchanged after failed reset");

    // Cleanup the consumed code row (it was recover_dek'd but reset failed, so row stays)
    // No cleanup needed — the test verifies the row is still there
}

#[test]
fn test_recover_dek_sqlite_error_propagates() {
    // SQLite errors other than QueryReturnedNoRows must propagate, not get swallowed as "code not found"
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // Don't create the table — any query will fail with a non-NoRows error
    let result = activity::recover_dek(&conn, "any-code");
    assert!(result.is_err(), "non-NoRows SQLite error must be an Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("database error"),
        "error must say 'database error', got: {}",
        msg
    );
    assert!(
        !msg.contains("invalid") && !msg.contains("wrong"),
        "must not be misreported as invalid code"
    );
}

#[test]
fn test_recover_dek_wrong_length_payload() {
    // Corrupted wrapped DEK with wrong plaintext length must error, not panic
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    activity::init_activity_table(&conn).unwrap();

    let _dek = vault::generate_dek();

    // Create a deliberately malformed wrapped DEK: valid AES-GCM of a 1-byte payload
    // (not a valid 32-byte DEK), stored with a known recovery code
    // A code in the real alphabet and normal form, as generate_recovery_codes makes them.
    let code = "ABCDEFGHJKLMNPQRSTUVWXYZ23";
    let hash = sha256_hash(code);

    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{Aes256Gcm, Nonce};
    use argon2::Argon2;
    use rand::RngCore;

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);

    let argon2 = Argon2::default();
    let mut recovery_key = [0u8; 32];
    argon2.hash_password_into(code.as_bytes(), &salt, &mut recovery_key).unwrap();

    // Encrypt a 1-byte payload (not 32) — this will produce wrong-length plaintext
    let cipher = Aes256Gcm::new_from_slice(&recovery_key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let bad_payload = b"x"; // 1 byte, not 32
    let ciphertext = cipher.encrypt(nonce, bad_payload.as_ref()).unwrap();
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    let wrapped = base64::engine::general_purpose::STANDARD.encode(&combined);

    conn.execute(
        "INSERT INTO recovery_codes (code_hash, salt, wrapped_dek) VALUES (?1, ?2, ?3)",
        rusqlite::params![hash, salt_b64, wrapped],
    ).unwrap();

    let result = activity::recover_dek(&conn, code);
    assert!(result.is_err(), "wrong-length DEK must error, not panic");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("corrupted DEK") || msg.contains("expected 32"),
        "error must mention corrupted/length, got: {}",
        msg
    );
}
