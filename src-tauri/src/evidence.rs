//! The evidence locker: files attached to a case, stored encrypted, with a
//! hash taken on the way in and a chain-of-custody record per file.
//!
//! Files live in `evidence/<id>.enc` beside the vault, never in the database,
//! so large captures and dumps are fine. Each file has its own random key,
//! sealed in the database under the vault key.
//!
//! File format: "ENCRAEV1", a 7-byte random nonce prefix, then the content in
//! 1 MiB chunks, each sealed with AES-256-GCM. A chunk's nonce is the prefix,
//! its position and a last-chunk flag, and its associated data names the
//! item, so chunks cannot be reordered, dropped, cut off or moved to another
//! item without failing to decrypt.
//!
//! Custody: every event (added, verified, exported, note) is an HMAC chain
//! entry over the one before it, keyed from the vault key, with a MAC of the
//! newest entry kept on the item. Editing, deleting, reordering or cutting
//! entries shows up as a broken chain.
//!
//! Limits, stated plainly: times come from this Mac's clock, and anyone with
//! the master password can rewrite everything. This is careful record
//! keeping, not a trusted timestamp.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use md5::Md5;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::fields;
use crate::util::{fill_random, uuid_v4};

pub const CHUNK: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"ENCRAEV1";
const PREFIX_LEN: usize = 7;
const TAG: usize = 16;
const ITEMS: &str = "evidence_items";
const CUSTODY: &str = "evidence_custody";
pub const MAX_NOTE_CHARS: usize = 4000;
const DAMAGED: &str = "the stored copy was altered or damaged";

pub fn init_tables(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS evidence_items (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            size TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            file_key TEXT NOT NULL,
            custody_head TEXT NOT NULL,
            added_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence_custody (
            id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            at TEXT NOT NULL,
            mac TEXT NOT NULL,
            UNIQUE (item_id, seq)
        );
        CREATE INDEX IF NOT EXISTS evidence_items_project ON evidence_items (project_id);",
    )
    .map_err(|e| e.to_string())
}

/// `evidence/` beside the vault file.
pub fn dir_for(db_path: &Path) -> PathBuf {
    db_path.parent().unwrap_or(Path::new(".")).join("evidence")
}

fn prepare_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create the evidence folder: {e}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn stored_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.enc"))
}

fn staging_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!(".{id}.tmp"))
}

// ===== Hashes =====

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[derive(Default)]
struct Hasher {
    sha256: Sha256,
    sha1: Sha1,
    md5: Md5,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha1.update(data);
        self.md5.update(data);
    }

    fn finish(self) -> Hashes {
        Hashes { sha256: hex(&self.sha256.finalize()), sha1: hex(&self.sha1.finalize()), md5: hex(&self.md5.finalize()) }
    }
}

// ===== Chunked encryption =====

fn nonce(prefix: &[u8; PREFIX_LEN], index: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = last as u8;
    nonce
}

fn file_aad(item_id: &str) -> String {
    format!("encra:evidence:v1:{item_id}")
}

/// Read until `buf` is full or the input ends.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Encrypt `reader` into `writer`, hashing the plaintext on the way. Only one
/// chunk is ever in memory. `progress` gets the bytes read so far.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: R,
    writer: &mut W,
    key: &[u8; 32],
    item_id: &str,
    progress: &mut dyn FnMut(u64),
) -> Result<(Hashes, u64), String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut prefix = [0u8; PREFIX_LEN];
    fill_random(&mut prefix);
    writer.write_all(MAGIC).and_then(|_| writer.write_all(&prefix)).map_err(|e| e.to_string())?;

    let aad = file_aad(item_id);
    let mut reader = BufReader::with_capacity(CHUNK, reader);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut hasher = Hasher::default();
    let mut total = 0u64;
    let mut index = 0u32;
    loop {
        let n = read_full(&mut reader, &mut buf).map_err(|e| format!("could not read the file: {e}"))?;
        let last = n < CHUNK || reader.fill_buf().map_err(|e| format!("could not read the file: {e}"))?.is_empty();
        hasher.update(&buf[..n]);
        total += n as u64;
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce(&prefix, index, last)), Payload { msg: &buf[..n], aad: aad.as_bytes() })
            .map_err(|e| e.to_string())?;
        writer.write_all(&sealed).map_err(|e| format!("could not write the evidence copy: {e}"))?;
        progress(total);
        if last {
            break;
        }
        index = index.checked_add(1).ok_or("the file is too large")?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    Ok((hasher.finish(), total))
}

/// Decrypt `reader` into `writer`, hashing the plaintext. Any change to the
/// stored copy fails here, before a wrong byte is trusted.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: R,
    writer: &mut W,
    key: &[u8; 32],
    item_id: &str,
    progress: &mut dyn FnMut(u64),
) -> Result<(Hashes, u64), String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut reader = BufReader::with_capacity(CHUNK + TAG, reader);
    let mut header = [0u8; MAGIC.len() + PREFIX_LEN];
    if read_full(&mut reader, &mut header).map_err(|e| e.to_string())? != header.len() || &header[..MAGIC.len()] != MAGIC {
        return Err(DAMAGED.into());
    }
    let prefix: [u8; PREFIX_LEN] = header[MAGIC.len()..].try_into().map_err(|_| DAMAGED)?;

    let aad = file_aad(item_id);
    let mut buf = vec![0u8; CHUNK + TAG];
    let mut hasher = Hasher::default();
    let mut total = 0u64;
    let mut index = 0u32;
    loop {
        let n = read_full(&mut reader, &mut buf).map_err(|e| e.to_string())?;
        if n < TAG {
            return Err(DAMAGED.into());
        }
        let last = n < CHUNK + TAG || reader.fill_buf().map_err(|e| e.to_string())?.is_empty();
        let plain = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce(&prefix, index, last)), Payload { msg: &buf[..n], aad: aad.as_bytes() })
                .map_err(|_| DAMAGED)?,
        );
        hasher.update(&plain);
        total += plain.len() as u64;
        writer.write_all(&plain).map_err(|e| format!("could not write the file: {e}"))?;
        progress(total);
        if last {
            break;
        }
        index = index.checked_add(1).ok_or(DAMAGED)?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    Ok((hasher.finish(), total))
}

// ===== Custody chain =====

type HmacSha256 = hmac::Hmac<Sha256>;

fn custody_key(dek: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    mac.update(b"encra:evidence-custody:v1");
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn hmac_hex(key: &[u8; 32], message: &str) -> String {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Covers the item and its intake hash, so an entry cannot be moved to
/// another item. The detail goes last: it is the only free text.
struct Entry<'a> {
    item_id: &'a str,
    sha256: &'a str,
    seq: i64,
    action: &'a str,
    at: &'a str,
    detail: &'a str,
}

fn entry_mac(key: &[u8; 32], prev: &str, e: &Entry) -> String {
    hmac_hex(key, &format!("{prev}\n{}\n{}\n{}\n{}\n{}\n{}", e.item_id, e.sha256, e.seq, e.action, e.at, e.detail))
}

fn head_mac(key: &[u8; 32], item_id: &str, seq: i64, mac: &str) -> String {
    hmac_hex(key, &format!("head\n{item_id}\n{seq}\n{mac}"))
}

fn now(db: &Connection) -> Result<String, String> {
    db.query_row("SELECT strftime('%Y-%m-%d %H:%M:%S', 'now')", [], |r| r.get(0)).map_err(|e| e.to_string())
}

/// Append a custody entry and move the item's head. Run inside the caller's
/// transaction.
fn append(db: &Connection, dek: &[u8; 32], item_id: &str, sha256: &str, action: &str, detail: &str) -> Result<(), String> {
    append_at(db, dek, item_id, sha256, action, detail, None)
}

fn append_at(db: &Connection, dek: &[u8; 32], item_id: &str, sha256: &str, action: &str, detail: &str, at: Option<&str>) -> Result<(), String> {
    let key = custody_key(dek);
    let last: Option<(i64, String)> = db
        .query_row("SELECT seq, mac FROM evidence_custody WHERE item_id = ?1 ORDER BY seq DESC LIMIT 1", [item_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .map_err(|e| e.to_string())?;
    let (seq, prev) = match last {
        Some((seq, mac)) => (seq + 1, mac),
        None => (1, String::new()),
    };
    let at = match at {
        Some(at) => at.to_string(),
        None => now(db)?,
    };
    let id = uuid_v4();
    let mac = entry_mac(&key, &prev, &Entry { item_id, sha256, seq, action, at: &at, detail });
    let sealed = fields::seal(dek, CUSTODY, &id, "detail", detail)?;
    db.execute(
        "INSERT INTO evidence_custody (id, item_id, seq, action, detail, at, mac) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, item_id, seq, action, sealed, at, mac],
    )
    .map_err(|e| e.to_string())?;
    let updated = db
        .execute("UPDATE evidence_items SET custody_head = ?1 WHERE id = ?2", rusqlite::params![head_mac(&key, item_id, seq, &mac), item_id])
        .map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("evidence not found".into());
    }
    Ok(())
}

#[derive(Debug, Serialize, PartialEq)]
pub struct CustodyEvent {
    pub seq: i64,
    pub action: String,
    pub detail: String,
    pub at: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct CustodyStatus {
    pub intact: bool,
    pub problem: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Custody {
    pub events: Vec<CustodyEvent>,
    pub status: CustodyStatus,
}

/// Every custody entry of an item, checked against the chain.
pub fn custody(db: &Connection, dek: &[u8; 32], item_id: &str) -> Result<Custody, String> {
    let item = load(db, dek, item_id)?;
    let head: String = db.query_row("SELECT custody_head FROM evidence_items WHERE id = ?1", [item_id], |r| r.get(0)).map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare("SELECT id, seq, action, detail, at, mac FROM evidence_custody WHERE item_id = ?1 ORDER BY seq, rowid")
        .map_err(|e| e.to_string())?;
    let rows: Vec<(String, i64, String, String, String, String)> = stmt
        .query_map([item_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;

    let key = custody_key(dek);
    let mut status = CustodyStatus { intact: true, problem: None };
    let mut fail = |problem: String| {
        if status.intact {
            status.intact = false;
            status.problem = Some(problem);
        }
    };
    let mut events = Vec::with_capacity(rows.len());
    let mut prev = String::new();
    for (index, (id, seq, action, sealed, at, mac)) in rows.into_iter().enumerate() {
        let expected = index as i64 + 1;
        if seq != expected {
            fail(format!("entry {expected} is missing or out of order"));
        }
        let detail = match fields::open_to_string(dek, CUSTODY, &id, "detail", &sealed) {
            Ok(detail) => detail,
            Err(_) => {
                fail(format!("entry {seq} could not be read"));
                String::new()
            }
        };
        let entry = Entry { item_id, sha256: &item.hashes.sha256, seq, action: &action, at: &at, detail: &detail };
        if entry_mac(&key, &prev, &entry) != mac {
            fail(format!("entry {seq} was changed"));
        }
        if index == 0 && action != "added" {
            fail("the first entry is not the intake".into());
        }
        events.push(CustodyEvent { seq, action, detail, at });
        prev = mac;
    }
    match events.last() {
        Some(last) if head == head_mac(&key, item_id, last.seq, &prev) => {}
        Some(_) => fail("the newest entries were removed".into()),
        None => fail("the custody record is empty".into()),
    }
    Ok(Custody { events, status })
}

// ===== Items =====

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub source: String,
    pub size: u64,
    pub hashes: Hashes,
    pub added_at: String,
    /// False when only the record exists here (restored from a backup).
    pub stored: bool,
}

fn row_to_item(dek: &[u8; 32], dir: Option<&Path>, row: &rusqlite::Row) -> rusqlite::Result<Result<Item, String>> {
    let id: String = row.get(0)?;
    let open = |column: &str, index: usize| -> rusqlite::Result<Result<String, String>> {
        let stored: String = row.get(index)?;
        Ok(fields::open_to_string(dek, ITEMS, &id, column, &stored))
    };
    let (name, source, size, sha256, sha1, md5) = (open("name", 2)?, open("source", 3)?, open("size", 4)?, open("sha256", 5)?, open("sha1", 6)?, open("md5", 7)?);
    let project_id: String = row.get(1)?;
    let added_at: String = row.get(8)?;
    Ok((|| {
        Ok(Item {
            stored: dir.map(|d| stored_path(d, &id).is_file()).unwrap_or(false),
            project_id,
            name: name?,
            source: source?,
            size: size?.parse().map_err(|_| "unreadable size")?,
            hashes: Hashes { sha256: sha256?, sha1: sha1?, md5: md5? },
            added_at,
            id,
        })
    })())
}

const ITEM_COLUMNS: &str = "id, project_id, name, source, size, sha256, sha1, md5, added_at";

/// One evidence record, without touching its file.
pub fn load(db: &Connection, dek: &[u8; 32], item_id: &str) -> Result<Item, String> {
    db.query_row(&format!("SELECT {ITEM_COLUMNS} FROM evidence_items WHERE id = ?1"), [item_id], |row| row_to_item(dek, None, row))
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "evidence not found".to_string())?
}

/// The evidence in a case, oldest first.
pub fn list(db: &Connection, dek: &[u8; 32], dir: &Path, project_id: &str) -> Result<Vec<Item>, String> {
    let mut stmt = db
        .prepare(&format!("SELECT {ITEM_COLUMNS} FROM evidence_items WHERE project_id = ?1 ORDER BY added_at, rowid"))
        .map_err(|e| e.to_string())?;
    let rows: Vec<Result<Item, String>> = stmt
        .query_map([project_id], |row| row_to_item(dek, Some(dir), row))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    rows.into_iter().collect()
}

fn file_key(db: &Connection, dek: &[u8; 32], item_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let stored: String = db
        .query_row("SELECT file_key FROM evidence_items WHERE id = ?1", [item_id], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or("evidence not found")?;
    let hex_key = fields::open(dek, ITEMS, item_id, "file_key", &stored)?;
    let mut key = Zeroizing::new([0u8; 32]);
    if hex_key.len() != 64 {
        return Err(DAMAGED.into());
    }
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex_key[i * 2..i * 2 + 2], 16).map_err(|_| DAMAGED)?;
    }
    Ok(key)
}

// ===== Intake =====

/// A file encrypted into the evidence folder but not yet recorded. Done
/// without the database lock, since a large file takes a while.
pub struct Staged {
    id: String,
    key: Zeroizing<[u8; 32]>,
    name: String,
    source: String,
    size: u64,
    hashes: Hashes,
}

/// Encrypt `source` into a staging file. The original is only read.
pub fn stage(dir: &Path, source: &Path, progress: &mut dyn FnMut(u64, u64)) -> Result<Staged, String> {
    let meta = std::fs::metadata(source).map_err(|e| format!("could not open that file: {e}"))?;
    if !meta.is_file() {
        return Err("only files can be added as evidence".into());
    }
    let total = meta.len();
    prepare_dir(dir)?;
    let id = uuid_v4();
    let mut key = Zeroizing::new([0u8; 32]);
    fill_random(key.as_mut());
    let staging = staging_path(dir, &id);
    let result = (|| {
        let input = File::open(source).map_err(|e| format!("could not open that file: {e}"))?;
        let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staging).map_err(|e| e.to_string())?;
        let (hashes, size) = encrypt_stream(input, &mut output, &key, &id, &mut |done| progress(done, total))?;
        output.sync_all().map_err(|e| e.to_string())?;
        Ok((hashes, size))
    })();
    match result {
        Ok((hashes, size)) => Ok(Staged {
            name: source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            source: source.to_string_lossy().into_owned(),
            id,
            key,
            size,
            hashes,
        }),
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            Err(error)
        }
    }
}

/// Throw a staged file away (the vault sealed while it was being read).
pub fn discard(dir: &Path, staged: Staged) {
    let _ = std::fs::remove_file(staging_path(dir, &staged.id));
}

/// Record a staged file in a case. The file is moved into place inside the
/// transaction; if anything fails, both the record and the file are gone.
/// A crash after the move but before the commit leaves an unrecorded file,
/// which `sweep` removes.
pub fn commit(db: &Connection, dek: &[u8; 32], dir: &Path, project_id: &str, staged: Staged, note: &str) -> Result<Item, String> {
    let staging = staging_path(dir, &staged.id);
    let stored = stored_path(dir, &staged.id);
    let result = crate::db::in_transaction(db, || {
        let exists: bool = db.query_row("SELECT EXISTS (SELECT 1 FROM projects WHERE id = ?1)", [project_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        if !exists {
            return Err("that case no longer exists".into());
        }
        let id = &staged.id;
        let seal = |column: &str, value: &str| fields::seal(dek, ITEMS, id, column, value);
        let key_hex = Zeroizing::new(hex(staged.key.as_ref()));
        let added_at = now(db)?;
        db.execute(
            "INSERT INTO evidence_items (id, project_id, name, source, size, sha256, sha1, md5, file_key, custody_head, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, '', ?10)",
            rusqlite::params![
                id,
                project_id,
                seal("name", &staged.name)?,
                seal("source", &staged.source)?,
                seal("size", &staged.size.to_string())?,
                seal("sha256", &staged.hashes.sha256)?,
                seal("sha1", &staged.hashes.sha1)?,
                seal("md5", &staged.hashes.md5)?,
                seal("file_key", &key_hex)?,
                added_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        let mut detail = format!("Added from {}", staged.source);
        if !note.trim().is_empty() {
            detail.push_str(&format!("\n{}", note.trim()));
        }
        append(db, dek, id, &staged.hashes.sha256, "added", &detail)?;
        std::fs::rename(&staging, &stored).map_err(|e| format!("could not store the evidence copy: {e}"))?;
        Ok(())
    });
    if let Err(error) = result {
        let _ = std::fs::remove_file(&staging);
        let _ = std::fs::remove_file(&stored);
        return Err(error);
    }
    crate::activity::log_action(db, "evidence_added", "a file was added to a case");
    load(db, dek, &staged.id).map(|mut item| {
        item.stored = true;
        item
    })
}

/// Remove staging files and stored files with no record: what a crash in the
/// middle of an intake or a delete leaves behind.
pub fn sweep(db: &Connection, dir: &Path) -> Result<usize, String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(0) };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let orphan = if name.starts_with('.') && name.ends_with(".tmp") {
            true
        } else if let Some(id) = name.strip_suffix(".enc") {
            let known: bool = db.query_row("SELECT EXISTS (SELECT 1 FROM evidence_items WHERE id = ?1)", [id], |r| r.get(0)).map_err(|e| e.to_string())?;
            !known
        } else {
            false
        };
        if orphan && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

// ===== Checking, exporting, notes, deleting =====

/// The outcome of a check, also written to the custody record.
#[derive(Debug, Serialize, PartialEq)]
pub struct Check {
    pub ok: bool,
    pub detail: String,
}

/// Decrypt the stored copy and compare its hashes with the intake hashes.
/// Needs only the item's key, so it runs without the database lock.
pub fn check(dir: &Path, item_id: &str, key: &[u8; 32], expected: &Hashes, progress: &mut dyn FnMut(u64)) -> Check {
    let file = match File::open(stored_path(dir, item_id)) {
        Ok(file) => file,
        Err(_) => return Check { ok: false, detail: "The stored copy is missing.".into() },
    };
    match decrypt_stream(file, &mut std::io::sink(), key, item_id, progress) {
        Ok((hashes, _)) if &hashes == expected => Check { ok: true, detail: "Hashes match the intake.".into() },
        Ok((hashes, _)) => Check { ok: false, detail: format!("SHA-256 is now {}.", hashes.sha256) },
        Err(_) => Check { ok: false, detail: "The stored copy was altered or damaged.".into() },
    }
}

/// What a check or export needs from the database: the item and its key.
pub fn open_item(db: &Connection, dek: &[u8; 32], item_id: &str) -> Result<(Item, Zeroizing<[u8; 32]>), String> {
    Ok((load(db, dek, item_id)?, file_key(db, dek, item_id)?))
}

/// Record a check in the custody chain.
pub fn record_check(db: &Connection, dek: &[u8; 32], item: &Item, check: &Check) -> Result<(), String> {
    let action = if check.ok { "verified" } else { "verify_failed" };
    crate::db::in_transaction(db, || append(db, dek, &item.id, &item.hashes.sha256, action, &check.detail))
}

/// Decrypt the stored copy to `dest`, through a temporary file next to it,
/// and only keep it if the hashes match the intake.
pub fn export_to(dir: &Path, item: &Item, key: &[u8; 32], dest: &Path, progress: &mut dyn FnMut(u64)) -> Check {
    let partial = dest.with_file_name(format!(".{}.encra-partial", dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
    let result = (|| {
        let input = File::open(stored_path(dir, &item.id)).map_err(|_| "The stored copy is missing.".to_string())?;
        let mut output = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&partial).map_err(|e| format!("Could not write there: {e}."))?;
        let (hashes, _) = decrypt_stream(input, &mut output, key, &item.id, progress).map_err(|_| "The stored copy was altered or damaged.".to_string())?;
        if hashes != item.hashes {
            return Err(format!("SHA-256 is now {}.", hashes.sha256));
        }
        output.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&partial, dest).map_err(|e| format!("Could not write there: {e}."))?;
        Ok(())
    })();
    match result {
        Ok(()) => Check { ok: true, detail: format!("Exported to {}. Hashes matched.", dest.display()) },
        Err(detail) => {
            let _ = std::fs::remove_file(&partial);
            Check { ok: false, detail }
        }
    }
}

pub fn record_export(db: &Connection, dek: &[u8; 32], item: &Item, check: &Check) -> Result<(), String> {
    let action = if check.ok { "exported" } else { "export_failed" };
    crate::db::in_transaction(db, || append(db, dek, &item.id, &item.hashes.sha256, action, &check.detail))
}

pub fn add_note(db: &Connection, dek: &[u8; 32], item_id: &str, note: &str) -> Result<(), String> {
    let note = note.trim();
    if note.is_empty() {
        return Err("note must not be empty".into());
    }
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err("note is too long".into());
    }
    let item = load(db, dek, item_id)?;
    crate::db::in_transaction(db, || append(db, dek, item_id, &item.hashes.sha256, "note", note))
}

/// Delete records inside the caller's transaction; returns the ids whose
/// files to remove once it commits.
pub fn delete_records(db: &Connection, item_ids: &[String]) -> Result<(), String> {
    for id in item_ids {
        db.execute("DELETE FROM evidence_custody WHERE item_id = ?1", [id]).map_err(|e| e.to_string())?;
        db.execute("DELETE FROM evidence_items WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn ids_in_case(db: &Connection, project_id: &str) -> Result<Vec<String>, String> {
    let mut stmt = db.prepare("SELECT id FROM evidence_items WHERE project_id = ?1").map_err(|e| e.to_string())?;
    let ids = stmt.query_map([project_id], |r| r.get(0)).map_err(|e| e.to_string())?.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    Ok(ids)
}

/// Remove stored copies after their records are gone. A failure here leaves
/// an orphan that `sweep` removes later.
pub fn remove_files(dir: &Path, item_ids: &[String]) {
    for id in item_ids {
        let _ = std::fs::remove_file(stored_path(dir, id));
    }
}

pub fn delete(db: &Connection, dir: &Path, item_id: &str) -> Result<(), String> {
    let ids = vec![item_id.to_string()];
    let exists: bool = db.query_row("SELECT EXISTS (SELECT 1 FROM evidence_items WHERE id = ?1)", [item_id], |r| r.get(0)).map_err(|e| e.to_string())?;
    if !exists {
        return Err("evidence not found".into());
    }
    crate::db::in_transaction(db, || delete_records(db, &ids))?;
    remove_files(dir, &ids);
    crate::activity::log_action(db, "evidence_deleted", "a file was removed from a case");
    Ok(())
}

// ===== Backups: the records, not the files =====

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct BackupCustodyEvent {
    pub action: String,
    pub detail: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct BackupEvidence {
    pub project_name: String,
    pub name: String,
    pub source: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub added_at: String,
    pub custody: Vec<BackupCustodyEvent>,
    /// What was wrong with the custody record when it was backed up.
    pub custody_problem: Option<String>,
}

/// Every evidence record, with its case by name, as a backup carries it.
pub fn backup_records(db: &Connection, dek: &[u8; 32], project_names: &std::collections::HashMap<String, String>) -> Result<Vec<BackupEvidence>, String> {
    let mut stmt = db.prepare("SELECT id FROM evidence_items ORDER BY added_at, rowid").map_err(|e| e.to_string())?;
    let ids: Vec<String> = stmt.query_map([], |r| r.get(0)).map_err(|e| e.to_string())?.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let item = load(db, dek, &id)?;
        let record = custody(db, dek, &id)?;
        out.push(BackupEvidence {
            project_name: project_names.get(&item.project_id).cloned().unwrap_or_default(),
            name: item.name,
            source: item.source,
            size: item.size,
            sha256: item.hashes.sha256,
            sha1: item.hashes.sha1,
            md5: item.hashes.md5,
            added_at: item.added_at,
            custody: record.events.into_iter().map(|e| BackupCustodyEvent { action: e.action, detail: e.detail, at: e.at }).collect(),
            custody_problem: record.status.problem,
        });
    }
    Ok(out)
}

/// Restore records inside the caller's transaction. The history is chained
/// again under this vault's key, which is only as trustworthy as the backup
/// itself (encrypted and authenticated), and a last entry says so.
pub fn restore_records(db: &Connection, dek: &[u8; 32], project_ids: &std::collections::HashMap<String, String>, records: &[BackupEvidence]) -> Result<(), String> {
    for record in records {
        let project_id = project_ids.get(&record.project_name).ok_or_else(|| format!("backup is inconsistent: evidence '{}' references a missing case", record.name))?;
        if record.custody.first().map(|e| e.action.as_str()) != Some("added") {
            return Err(format!("backup is inconsistent: evidence '{}' has no intake record", record.name));
        }
        let id = uuid_v4();
        let seal = |column: &str, value: &str| fields::seal(dek, ITEMS, &id, column, value);
        // No file comes with the record, so its key protects nothing; it is
        // random so the column is never a known value.
        let mut unused = [0u8; 32];
        fill_random(&mut unused);
        db.execute(
            "INSERT INTO evidence_items (id, project_id, name, source, size, sha256, sha1, md5, file_key, custody_head, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, '', ?10)",
            rusqlite::params![
                id,
                project_id,
                seal("name", &record.name)?,
                seal("source", &record.source)?,
                seal("size", &record.size.to_string())?,
                seal("sha256", &record.sha256)?,
                seal("sha1", &record.sha1)?,
                seal("md5", &record.md5)?,
                seal("file_key", &hex(&unused))?,
                record.added_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        for event in &record.custody {
            append_at(db, dek, &id, &record.sha256, &event.action, &event.detail, Some(&event.at))?;
        }
        let mut detail = "Restored from a backup. The file itself was not in the backup.".to_string();
        if let Some(problem) = &record.custody_problem {
            detail.push_str(&format!(" The custody record was already broken when backed up: {problem}."));
        }
        append(db, dek, &id, &record.sha256, "restored", &detail)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK: [u8; 32] = [7u8; 32];

    struct Rig {
        dir: PathBuf,
        db_path: PathBuf,
        db: Connection,
    }

    impl Rig {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("encra-evidence-{label}-{}", uuid_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let db_path = dir.join("encra.db");
            let db = Self::open(&db_path);
            let name = fields::seal(&DEK, "projects", "case1", "name", "Lab 3").unwrap();
            db.execute("INSERT INTO projects (id, name) VALUES ('case1', ?1)", [&name]).unwrap();
            Rig { dir, db_path, db }
        }

        fn open(path: &Path) -> Connection {
            let db = crate::vault::init_db(path).unwrap();
            crate::journal::init_journal_tables(&db).unwrap();
            crate::activity::init_activity_table(&db).unwrap();
            init_tables(&db).unwrap();
            db
        }

        fn reopen(&mut self) {
            self.db = Self::open(&self.db_path);
        }

        fn evidence_dir(&self) -> PathBuf {
            dir_for(&self.db_path)
        }

        fn add(&self, content: &[u8], note: &str) -> Item {
            let source = self.dir.join("capture.pcap");
            std::fs::write(&source, content).unwrap();
            let staged = stage(&self.evidence_dir(), &source, &mut |_, _| {}).unwrap();
            commit(&self.db, &DEK, &self.evidence_dir(), "case1", staged, note).unwrap()
        }

        fn stored(&self, item: &Item) -> PathBuf {
            stored_path(&self.evidence_dir(), &item.id)
        }

        fn check(&self, item: &Item) -> Check {
            let (item, key) = open_item(&self.db, &DEK, &item.id).unwrap();
            check(&self.evidence_dir(), &item.id, &key, &item.hashes, &mut |_| {})
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn roundtrip(data: &[u8]) -> (Vec<u8>, Hashes, Vec<u8>) {
        let key = [3u8; 32];
        let mut sealed = Vec::new();
        let (hashes, size) = encrypt_stream(data, &mut sealed, &key, "item", &mut |_| {}).unwrap();
        assert_eq!(size, data.len() as u64);
        let mut plain = Vec::new();
        let (again, _) = decrypt_stream(sealed.as_slice(), &mut plain, &key, "item", &mut |_| {}).unwrap();
        assert_eq!(hashes, again);
        (plain, hashes, sealed)
    }

    #[test]
    fn test_hashes_match_known_values() {
        let (_, hashes, _) = roundtrip(b"abc");
        assert_eq!(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_every_size_around_a_chunk_round_trips() {
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (plain, _, sealed) = roundtrip(&data);
            assert_eq!(plain, data, "size {size}");
            let chunks = size.div_ceil(CHUNK).max(1);
            assert_eq!(sealed.len(), MAGIC.len() + PREFIX_LEN + size + chunks * TAG, "size {size}");
        }
    }

    #[test]
    fn test_a_large_file_streams_through_one_chunk_at_a_time() {
        // 16 MiB generated on the fly and hashed on the way out: neither side
        // ever holds the whole file.
        struct Pattern(u64);
        impl Read for Pattern {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.0 as usize).min(4096);
                buf[..n].fill((self.0 % 251) as u8);
                self.0 -= n as u64;
                Ok(n)
            }
        }
        let key = [9u8; 32];
        let size = 16 * CHUNK as u64;
        let path = std::env::temp_dir().join(format!("encra-evidence-large-{}", uuid_v4()));
        let mut file = File::create(&path).unwrap();
        let mut steps = 0;
        let (hashes, total) = encrypt_stream(Pattern(size), &mut file, &key, "big", &mut |_| steps += 1).unwrap();
        assert_eq!((total, steps), (size, 16), "one progress step per chunk");
        let (again, total) = decrypt_stream(File::open(&path).unwrap(), &mut std::io::sink(), &key, "big", &mut |_| {}).unwrap();
        assert_eq!((again, total), (hashes, size));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_any_change_to_a_stored_copy_is_caught() {
        let data: Vec<u8> = (0..3 * CHUNK + 100).map(|i| (i % 253) as u8).collect();
        let (_, _, sealed) = roundtrip(&data);
        let key = [3u8; 32];
        let header = MAGIC.len() + PREFIX_LEN;
        let chunk = CHUNK + TAG;
        let open = |bytes: &[u8], key: &[u8; 32], item: &str| decrypt_stream(bytes, &mut std::io::sink(), key, item, &mut |_| {});

        let mut flipped = sealed.clone();
        flipped[header + chunk + 10] ^= 1;
        let mut swapped = sealed.clone();
        swapped[header..header + 2 * chunk].rotate_left(chunk);
        let cut_at_boundary = &sealed[..header + 2 * chunk];
        let cut_mid = &sealed[..sealed.len() - 7];
        let mut extended = sealed.clone();
        extended.extend_from_slice(&[0u8; 40]);
        let mut bad_magic = sealed.clone();
        bad_magic[0] = b'X';

        for (bytes, what) in [
            (flipped.as_slice(), "a flipped byte"),
            (swapped.as_slice(), "swapped chunks"),
            (cut_at_boundary, "cut at a chunk boundary"),
            (cut_mid, "cut mid-chunk"),
            (extended.as_slice(), "bytes appended"),
            (bad_magic.as_slice(), "a damaged header"),
            (&sealed[..10], "only part of the header"),
            (&sealed[..header], "no chunks at all"),
        ] {
            assert_eq!(open(bytes, &key, "item").unwrap_err(), DAMAGED, "{what}");
        }
        assert!(open(&sealed, &[4u8; 32], "item").is_err(), "another key");
        assert!(open(&sealed, &key, "other-item").is_err(), "moved to another item");
        assert!(open(&sealed, &key, "item").is_ok());
    }

    #[test]
    fn test_intake_survives_reopen_and_verifies() {
        let mut rig = Rig::new("intake");
        let content = b"GET /admin HTTP/1.1\r\nHost: 10.10.10.5\r\n\r\n".repeat(1000);
        let item = rig.add(&content, "From the web server, 7 November");
        assert!(item.stored);
        assert_eq!(item.name, "capture.pcap");
        assert_eq!(item.size, content.len() as u64);
        let original = std::fs::read(rig.dir.join("capture.pcap")).unwrap();
        assert_eq!(original, content, "the original is left alone");
        let mode = std::fs::metadata(rig.stored(&item)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        rig.reopen();
        let listed = list(&rig.db, &DEK, &rig.evidence_dir(), "case1").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hashes, item.hashes);
        let result = rig.check(&item);
        assert!(result.ok, "{}", result.detail);
        record_check(&rig.db, &DEK, &item, &result).unwrap();
        add_note(&rig.db, &DEK, &item.id, "Handed to the lab instructor").unwrap();

        let exported = rig.dir.join("out.pcap");
        let (loaded, key) = open_item(&rig.db, &DEK, &item.id).unwrap();
        let result = export_to(&rig.evidence_dir(), &loaded, &key, &exported, &mut |_| {});
        assert!(result.ok, "{}", result.detail);
        record_export(&rig.db, &DEK, &item, &result).unwrap();
        assert_eq!(std::fs::read(&exported).unwrap(), content);

        rig.reopen();
        let record = custody(&rig.db, &DEK, &item.id).unwrap();
        assert!(record.status.intact, "{:?}", record.status.problem);
        let actions: Vec<&str> = record.events.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["added", "verified", "note", "exported"]);
        assert!(record.events[0].detail.contains("From the web server"));

        // Nothing in the database is readable without the key.
        let raw: String = rig.db.query_row("SELECT name || source || sha256 || file_key FROM evidence_items", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("capture") && !raw.contains(&item.hashes.sha256));
        let detail: String = rig.db.query_row("SELECT detail FROM evidence_custody WHERE seq = 3", [], |r| r.get(0)).unwrap();
        assert!(!detail.contains("instructor"));
    }

    #[test]
    fn test_a_changed_stored_copy_fails_verification_and_export() {
        let rig = Rig::new("tamper-file");
        let item = rig.add(&vec![42u8; CHUNK + 10], "");
        let mut bytes = std::fs::read(rig.stored(&item)).unwrap();
        bytes[100] ^= 0xff;
        std::fs::write(rig.stored(&item), bytes).unwrap();

        let result = rig.check(&item);
        assert!(!result.ok);
        record_check(&rig.db, &DEK, &item, &result).unwrap();
        let out = rig.dir.join("out.bin");
        let (loaded, key) = open_item(&rig.db, &DEK, &item.id).unwrap();
        assert!(!export_to(&rig.evidence_dir(), &loaded, &key, &out, &mut |_| {}).ok);
        assert!(!out.exists(), "a failed export leaves nothing behind");
        assert_eq!(std::fs::read_dir(&rig.dir).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains("partial")).count(), 0);

        std::fs::remove_file(rig.stored(&item)).unwrap();
        assert_eq!(rig.check(&item).detail, "The stored copy is missing.");
        assert_eq!(custody(&rig.db, &DEK, &item.id).unwrap().events.last().unwrap().action, "verify_failed");
    }

    #[test]
    fn test_a_changed_custody_record_shows_as_broken() {
        let tamper = |label: &str, sql: &str, problem: &str| {
            let rig = Rig::new(label);
            let item = rig.add(b"memory dump", "");
            add_note(&rig.db, &DEK, &item.id, "first").unwrap();
            add_note(&rig.db, &DEK, &item.id, "second").unwrap();
            assert!(custody(&rig.db, &DEK, &item.id).unwrap().status.intact);
            rig.db.execute(sql, []).unwrap();
            let status = custody(&rig.db, &DEK, &item.id).unwrap().status;
            assert!(!status.intact, "{label}");
            assert!(status.problem.as_deref().unwrap_or_default().contains(problem), "{label}: {:?}", status.problem);
        };
        tamper("edit-time", "UPDATE evidence_custody SET at = '2020-01-01 00:00:00' WHERE seq = 2", "entry 2 was changed");
        tamper("edit-action", "UPDATE evidence_custody SET action = 'verified' WHERE seq = 2", "entry 2 was changed");
        tamper("drop-middle", "DELETE FROM evidence_custody WHERE seq = 2", "entry 2 is missing");
        tamper("drop-last", "DELETE FROM evidence_custody WHERE seq = 3", "newest entries were removed");
        tamper("swap-detail", "UPDATE evidence_custody SET detail = (SELECT detail FROM evidence_custody WHERE seq = 3) WHERE seq = 2", "entry 2 could not be read");
    }

    #[test]
    fn test_custody_entries_cannot_move_between_items() {
        let rig = Rig::new("move");
        let first = rig.add(b"one", "");
        let second = rig.add(b"two", "");
        // Give the first item the second item's intake entry.
        rig.db.execute("DELETE FROM evidence_custody WHERE item_id = ?1", [&first.id]).unwrap();
        rig.db.execute("UPDATE evidence_custody SET item_id = ?1 WHERE item_id = ?2", [&first.id, &second.id]).unwrap();
        let status = custody(&rig.db, &DEK, &first.id).unwrap().status;
        assert_eq!(status.problem.as_deref(), Some("entry 1 was changed"));
    }

    #[test]
    fn test_failed_and_interrupted_intakes_leave_nothing_behind() {
        let rig = Rig::new("crash");
        let source = rig.dir.join("log.txt");
        std::fs::write(&source, b"auth.log").unwrap();
        let dir = rig.evidence_dir();

        // The case was deleted while the file was being read.
        let staged = stage(&dir, &source, &mut |_, _| {}).unwrap();
        assert!(commit(&rig.db, &DEK, &dir, "no-such-case", staged, "").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(rig.db.query_row("SELECT COUNT(*) FROM evidence_items", [], |r| r.get::<_, i64>(0)).unwrap(), 0);

        // A database failure mid-commit rolls back and removes the file.
        let staged = stage(&dir, &source, &mut |_, _| {}).unwrap();
        rig.db.execute_batch("CREATE TRIGGER fail_custody BEFORE INSERT ON evidence_custody BEGIN SELECT RAISE(ABORT, 'forced'); END;").unwrap();
        assert!(commit(&rig.db, &DEK, &dir, "case1", staged, "").is_err());
        rig.db.execute_batch("DROP TRIGGER fail_custody").unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(rig.db.query_row("SELECT COUNT(*) FROM evidence_items", [], |r| r.get::<_, i64>(0)).unwrap(), 0);

        // A crash after staging, and one after the move: swept on next start.
        let _abandoned = stage(&dir, &source, &mut |_, _| {}).unwrap();
        std::fs::write(stored_path(&dir, "never-recorded"), b"x").unwrap();
        let kept = rig.add(b"kept", "");
        assert_eq!(sweep(&rig.db, &dir).unwrap(), 2);
        assert!(rig.stored(&kept).exists());
        assert!(rig.check(&kept).ok);

        // Folders and missing files are refused before anything is written.
        assert!(stage(&dir, &rig.dir, &mut |_, _| {}).is_err());
        assert!(stage(&dir, &rig.dir.join("nope"), &mut |_, _| {}).is_err());
    }

    #[test]
    fn test_delete_removes_record_and_file() {
        let rig = Rig::new("delete");
        let item = rig.add(b"to remove", "");
        delete(&rig.db, &rig.evidence_dir(), &item.id).unwrap();
        assert!(!rig.stored(&item).exists());
        assert!(list(&rig.db, &DEK, &rig.evidence_dir(), "case1").unwrap().is_empty());
        assert_eq!(rig.db.query_row("SELECT COUNT(*) FROM evidence_custody", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert!(delete(&rig.db, &rig.evidence_dir(), &item.id).is_err());
        assert!(add_note(&rig.db, &DEK, &item.id, "late").is_err());
    }

    #[test]
    fn test_notes_are_checked() {
        let rig = Rig::new("notes");
        let item = rig.add(b"x", "");
        assert!(add_note(&rig.db, &DEK, &item.id, "   ").is_err());
        assert!(add_note(&rig.db, &DEK, &item.id, &"a".repeat(MAX_NOTE_CHARS + 1)).is_err());
        assert!(add_note(&rig.db, &[1u8; 32], &item.id, "wrong key").is_err(), "a wrong key cannot add to the record");
    }
}
