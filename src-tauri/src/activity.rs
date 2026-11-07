use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use base64::Engine;
use rand::RngCore;
use zeroize::Zeroize;

use crate::util::{os_rng, uuid_v4};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActivityEntry {
    pub id: String,
    pub action: String,
    pub detail: String,
    pub timestamp: String,
}

const RECOVERY_CODE_COUNT: usize = 8;
/// 26 chars × 5 bits = 130 bits of entropy, above the 128-bit floor.
const RECOVERY_CODE_CHARS: usize = 26;

pub fn init_activity_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS activity_log (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            timestamp TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            salt TEXT NOT NULL DEFAULT '',
            wrapped_dek TEXT NOT NULL DEFAULT ''
        );",
    )
    .map_err(|e| e.to_string())?;

    // Migration: add columns if upgrading from old recovery_codes schema
    conn.execute("ALTER TABLE recovery_codes ADD COLUMN salt TEXT NOT NULL DEFAULT ''", []).ok();
    conn.execute("ALTER TABLE recovery_codes ADD COLUMN wrapped_dek TEXT NOT NULL DEFAULT ''", []).ok();
    // Format 3: position in the chain, and the entry's HMAC once sealed.
    conn.execute("ALTER TABLE activity_log ADD COLUMN seq INTEGER", []).ok();
    conn.execute("ALTER TABLE activity_log ADD COLUMN mac TEXT", []).ok();

    Ok(())
}

pub fn log_action(conn: &Connection, action: &str, detail: &str) {
    // A pair of random u64s collides readily at scale, and this insert is
    // best-effort, so a collision would silently drop an audit entry.
    let id = uuid_v4();
    conn.execute(
        "INSERT INTO activity_log (id, action, detail, seq)
         VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq), 0) + 1 FROM activity_log))",
        rusqlite::params![id, action, detail],
    )
    .ok();
}

// ===== The HMAC chain (vault format 3) =====
//
// Each entry is sealed with HMAC-SHA256 over the previous entry's MAC, its own
// position and contents, keyed from the data key. Without the master password
// nobody can recompute the chain, so editing, inserting, reordering or
// deleting a sealed entry shows up when it is verified. A MAC over the newest
// sealed entry ("the head") is kept in vault_config, so cutting entries off
// the end shows up too.
//
// Limit: entries written while the vault is locked (failed unlocks) cannot be
// sealed until the next unlock. Until then someone with the file could delete
// them or add fake ones; they cannot touch anything already sealed.

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

fn log_key(dek: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    mac.update(b"encra:activity-log:v1");
    zeroize::Zeroizing::new(mac.finalize().into_bytes().into())
}

fn hmac_hex(key: &[u8; 32], message: &str) -> String {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn entry_mac(key: &[u8; 32], prev: &str, seq: i64, action: &str, timestamp: &str, detail: &str) -> String {
    // Detail goes last: it is the only part that could contain a newline.
    hmac_hex(key, &format!("{prev}\n{seq}\n{action}\n{timestamp}\n{detail}"))
}

fn head_mac(key: &[u8; 32], seq: i64, mac: &str) -> String {
    hmac_hex(key, &format!("head\n{seq}\n{mac}"))
}

/// Number entries 1..n in the order they were written. Run once, inside the
/// format-3 migration, before anything is sealed.
pub fn renumber(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn.prepare("SELECT rowid FROM activity_log ORDER BY rowid").map_err(|e| e.to_string())?;
    let rowids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for (index, rowid) in rowids.iter().enumerate() {
        conn.execute("UPDATE activity_log SET seq = ?1, mac = NULL WHERE rowid = ?2", rusqlite::params![index as i64 + 1, rowid])
            .map_err(|e| e.to_string())?;
    }
    conn.execute("DELETE FROM vault_config WHERE key = 'log_head'", []).map_err(|e| e.to_string())?;
    Ok(())
}

struct ChainRow {
    seq: Option<i64>,
    action: String,
    detail: String,
    timestamp: String,
    mac: Option<String>,
}

fn chain_rows(conn: &Connection) -> Result<Vec<ChainRow>, String> {
    let mut stmt = conn
        .prepare("SELECT seq, action, COALESCE(detail, ''), timestamp, mac FROM activity_log ORDER BY seq, rowid")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ChainRow { seq: row.get(0)?, action: row.get(1)?, detail: row.get(2)?, timestamp: row.get(3)?, mac: row.get(4)? })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

/// Seal every pending entry, in order, and move the head. Returns how many
/// were sealed.
///
/// Refuses on a broken chain. Sealing extends whatever is there and moves the
/// head, so sealing on top of, say, a cut-off tail would make the cut look
/// legitimate. Left pending, the damage stays visible.
pub fn seal_pending(conn: &Connection, dek: &[u8; 32]) -> Result<usize, String> {
    let status = verify_chain(conn, dek)?;
    if !status.intact {
        return Err(format!("not sealing a broken chain: {}", status.problem.unwrap_or_default()));
    }
    if status.pending == 0 {
        return Ok(0);
    }
    let key = log_key(dek);
    let rows = chain_rows(conn)?;
    let mut prev = String::new();
    let mut sealed = 0;
    let mut head: Option<(i64, String)> = None;
    for row in rows {
        let Some(seq) = row.seq else { continue };
        match row.mac {
            Some(mac) => prev = mac,
            None => {
                let mac = entry_mac(&key, &prev, seq, &row.action, &row.timestamp, &row.detail);
                conn.execute("UPDATE activity_log SET mac = ?1 WHERE seq = ?2 AND mac IS NULL", rusqlite::params![mac, seq])
                    .map_err(|e| e.to_string())?;
                prev = mac.clone();
                head = Some((seq, mac));
                sealed += 1;
            }
        }
    }
    if let Some((seq, mac)) = head {
        conn.execute(
            "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('log_head', ?1)",
            [format!("{seq}:{}", head_mac(&key, seq, &mac))],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(sealed)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ChainStatus {
    pub intact: bool,
    pub sealed: usize,
    /// Written while locked; sealed at the next unlock.
    pub pending: usize,
    /// What is wrong, in plain words, when `intact` is false.
    pub problem: Option<String>,
}

/// Check the whole chain against the data key.
pub fn verify_chain(conn: &Connection, dek: &[u8; 32]) -> Result<ChainStatus, String> {
    let key = log_key(dek);
    let rows = chain_rows(conn)?;
    let mut status = ChainStatus { intact: true, sealed: 0, pending: 0, problem: None };
    let fail = |status: &mut ChainStatus, problem: String| {
        if status.intact {
            status.intact = false;
            status.problem = Some(problem);
        }
    };

    let mut prev = String::new();
    let mut last_sealed: Option<(i64, String)> = None;
    for (index, row) in rows.iter().enumerate() {
        let expected = index as i64 + 1;
        let Some(seq) = row.seq else {
            fail(&mut status, "an entry without a position was added".into());
            continue;
        };
        if seq != expected {
            fail(&mut status, format!("entry {expected} is missing or out of order"));
        }
        match &row.mac {
            Some(mac) => {
                if status.pending > 0 {
                    fail(&mut status, format!("entry {seq} was sealed after unsealed entries"));
                }
                if entry_mac(&key, &prev, seq, &row.action, &row.timestamp, &row.detail) != *mac {
                    fail(&mut status, format!("entry {seq} was changed"));
                }
                prev = mac.clone();
                last_sealed = Some((seq, mac.clone()));
                status.sealed += 1;
            }
            None => status.pending += 1,
        }
    }

    let head: Option<String> = conn
        .query_row("SELECT value FROM vault_config WHERE key = 'log_head'", [], |row| row.get(0))
        .ok();
    match (last_sealed, head) {
        (None, None) => {}
        (Some((seq, mac)), Some(stored)) => {
            if stored != format!("{seq}:{}", head_mac(&key, seq, &mac)) {
                fail(&mut status, "the newest sealed entries were removed".into());
            }
        }
        (Some(_), None) => fail(&mut status, "the record of the newest sealed entry is missing".into()),
        (None, Some(_)) => fail(&mut status, "sealed entries were removed".into()),
    }
    Ok(status)
}

/// Generate recovery codes that can recover the DEK from locked state.
/// Each code: random salt → argon2id key → AES-256-GCM wrap the DEK.
/// Store: SHA-256 hash of the code (for lookup), salt, wrapped DEK.
///
/// The delete-and-replace is transactional: a failure part-way through can no
/// longer leave the vault with its existing codes deleted and none written.
pub fn generate_recovery_codes(conn: &Connection, dek: &[u8; 32]) -> Result<Vec<String>, String> {
    use rand::Rng;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use argon2::Argon2;

    // Phase 1 — derive everything in memory before touching the database.
    let charset: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut codes: Vec<String> = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut rows: Vec<(String, String, String)> = Vec::with_capacity(RECOVERY_CODE_COUNT);

    for _ in 0..RECOVERY_CODE_COUNT {
        let code: String = (0..RECOVERY_CODE_CHARS)
            .map(|_| charset[os_rng().gen_range(0..charset.len())])
            .collect();

        let mut salt = [0u8; 32];
        os_rng().fill_bytes(&mut salt);
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);

        let argon2 = Argon2::default();
        let mut recovery_key = [0u8; 32];
        argon2
            .hash_password_into(code.as_bytes(), &salt, &mut recovery_key)
            .map_err(|e| e.to_string())?;

        let cipher = Aes256Gcm::new_from_slice(&recovery_key).map_err(|e| e.to_string())?;
        let mut nonce_bytes = [0u8; 12];
        os_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, dek.as_ref()).map_err(|e| e.to_string())?;
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        recovery_key.zeroize();

        let wrapped = base64::engine::general_purpose::STANDARD.encode(&combined);
        rows.push((sha256_hash(&code), salt_b64, wrapped));
        codes.push(code);
    }

    // Phase 2 — one transaction for the delete and every insert.
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| e.to_string())?;
    let write = || -> Result<(), String> {
        conn.execute("DELETE FROM recovery_codes", []).map_err(|e| e.to_string())?;
        for (hash, salt_b64, wrapped) in &rows {
            conn.execute(
                "INSERT INTO recovery_codes (code_hash, salt, wrapped_dek) VALUES (?1, ?2, ?3)",
                rusqlite::params![hash, salt_b64, wrapped],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    };

    if let Err(e) = write() {
        conn.execute("ROLLBACK", []).ok();
        return Err(format!("failed to store recovery codes: {e}"));
    }
    if conn.execute("COMMIT", []).is_err() {
        conn.execute("ROLLBACK", []).ok();
        return Err("failed to commit recovery codes".into());
    }

    Ok(codes)
}

/// Try to recover the DEK using a recovery code. Works from locked state.
/// Returns Ok(Some((dek, row_id))) on success, Ok(None) if code not found, Err on crypto failure.
///
/// Does NOT consume the code and does not open a transaction, so it can be called
/// inside a caller-managed transaction. Prefer `recover_and_reset`, which does
/// the lookup, the password change, and the consumption in one atomic step.
/// Undo the ways a person writes a code down: spaces or dashes between
/// groups, lowercase. Codes only contain uppercase letters and digits, so this
/// can never turn one valid code into another.
pub fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn recover_dek(conn: &Connection, code: &str) -> Result<Option<([u8; 32], i64)>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use argon2::Argon2;

    // Normalise once, so the hash lookup and the key derivation see the same
    // code.
    let code = zeroize::Zeroizing::new(normalize_recovery_code(code));
    let code = code.as_str();
    let hash = sha256_hash(code);

    let result = conn.query_row(
        "SELECT salt, wrapped_dek, id FROM recovery_codes WHERE code_hash = ?1 LIMIT 1",
        rusqlite::params![hash],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    );

    let (salt_b64, wrapped_b64, row_id) = match result {
        Ok(tuple) => tuple,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(format!("database error: {}", e)),
    };

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&salt_b64)
        .map_err(|e| e.to_string())?;

    let combined = base64::engine::general_purpose::STANDARD
        .decode(&wrapped_b64)
        .map_err(|e| e.to_string())?;

    if combined.len() < 12 {
        return Err("corrupted wrapped DEK".into());
    }

    // Derive recovery key from code + salt
    let argon2 = Argon2::default();
    let mut recovery_key = [0u8; 32];
    argon2
        .hash_password_into(code.as_bytes(), &salt, &mut recovery_key)
        .map_err(|e| e.to_string())?;

    // Unwrap DEK
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&recovery_key).map_err(|e| e.to_string())?;
    let mut dek_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong recovery code or corrupted wrapped DEK".to_string())?;
    recovery_key.zeroize();

    if dek_bytes.len() != 32 {
        let len = dek_bytes.len();
        dek_bytes.zeroize();
        return Err(format!("corrupted DEK: expected 32 bytes, got {len}"));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    dek_bytes.zeroize();

    Ok(Some((dek, row_id)))
}

fn sha256_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Write the new wrapping material and consume the recovery code.
///
/// Performs no transaction management of its own, so it can be composed into a
/// larger atomic operation. Callers must hold a transaction open.
fn apply_recovery_reset(
    conn: &Connection,
    dek: &[u8; 32],
    new_password: &str,
    row_id: i64,
) -> Result<(), String> {
    use crate::vault;

    // Generate new random KDF salt
    let mut new_salt = [0u8; 32];
    os_rng().fill_bytes(&mut new_salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(new_salt);

    let mut wrapping_key = vault::derive_key_with(new_password, &new_salt, vault::KdfParams::CURRENT)?;
    let wrapped = vault::wrap_dek(dek, &wrapping_key);
    wrapping_key.zeroize();
    let wrapped = wrapped?;
    let pass_hash = vault::hash_password_with(new_password, vault::KdfParams::CURRENT)?;

    conn.execute(
        "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)",
        rusqlite::params![wrapped],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)",
        rusqlite::params![pass_hash],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)",
        rusqlite::params![salt_b64],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_params', ?1)",
        rusqlite::params![vault::KdfParams::CURRENT.encode()],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM recovery_codes WHERE id = ?1",
        rusqlite::params![row_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

/// Recover the DEK with a recovery code and reset the master password in a
/// single transaction.
///
/// The code lookup, the password change, and the code deletion all commit
/// together, so a one-time code cannot be consumed without the reset taking
/// effect, and the reset cannot take effect while the code survives. Two
/// concurrent callers cannot both succeed: the second sees the row already gone.
///
/// Returns Ok(None) when the code does not match any stored code.
pub fn recover_and_reset(
    conn: &Connection,
    code: &str,
    new_password: &str,
) -> Result<Option<[u8; 32]>, String> {
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| e.to_string())?;

    let recovered = match recover_dek(conn, code) {
        Ok(value) => value,
        Err(e) => {
            conn.execute("ROLLBACK", []).ok();
            return Err(e);
        }
    };

    let (dek, row_id) = match recovered {
        Some(tuple) => tuple,
        None => {
            conn.execute("ROLLBACK", []).ok();
            return Ok(None);
        }
    };

    if let Err(e) = apply_recovery_reset(conn, &dek, new_password, row_id) {
        conn.execute("ROLLBACK", []).ok();
        return Err(format!("recovery reset failed: {}", e));
    }
    if conn.execute("COMMIT", []).is_err() {
        conn.execute("ROLLBACK", []).ok();
        return Err("commit failed".into());
    }

    Ok(Some(dek))
}