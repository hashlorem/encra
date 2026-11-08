use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use crate::util::uuid_v4;
use crate::{fields, vault};

/// Payload version.
///
/// `1.0` — only the credential password was exported in the clear; every other
/// sensitive field was the source vault's raw ciphertext, so a backup could only
/// ever be restored into the vault that produced it.
/// `1.1` — every sensitive field is exported as plaintext inside the encrypted
/// envelope and re-encrypted with the destination vault's key on import, so a
/// backup is portable between vaults with different master passwords.
const BACKUP_VERSION: &str = "1.1";
const LEGACY_BACKUP_VERSION: &str = "1.0";

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultBackup {
    pub version: String,
    pub credentials: Vec<BackupCredential>,
    pub projects: Vec<BackupProject>,
    pub journal_entries: Vec<BackupJournalEntry>,
    pub kb_entries: Vec<BackupKBEntry>,
    /// Evidence records and custody history, without the files. Absent in
    /// backups made before the evidence locker.
    #[serde(default)]
    pub evidence: Vec<crate::evidence::BackupEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupCredential {
    pub service: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupProject {
    pub name: String,
    pub description: String,
    pub target: String,
    pub methodology: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupJournalEntry {
    pub project_name: String,
    pub title: String,
    pub content: String,
    pub entry_type: String,
    pub severity: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupKBEntry {
    pub title: String,
    pub command: String,
    pub description: String,
    pub tags: String,
    pub category: String,
}

/// Where a stored value lives, for its binding.
struct Place<'a> {
    table: &'a str,
    id: &'a str,
}

fn decrypt_field(dek: &[u8; 32], place: &Place, column: &str, value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    fields::open_to_string(dek, place.table, place.id, column, value).map_err(|_| {
        format!(
            "failed to decrypt {label} while building the backup — the vault may be corrupted"
        )
    })
}

fn decrypt_optional_field(
    dek: &[u8; 32],
    place: &Place,
    column: &str,
    value: &Option<String>,
    label: &str,
) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(raw) if raw.is_empty() => Ok(Some(String::new())),
        Some(raw) => Ok(Some(decrypt_field(dek, place, column, raw, label)?)),
    }
}

/// Read every table into a plaintext backup structure.
///
/// Every sensitive field is decrypted here so the serialized payload — which is
/// then encrypted wholesale under the backup password — is portable.
/// A field that cannot be decrypted fails the export instead of being replaced
/// with a placeholder, so a corrupt vault cannot silently overwrite good data on
/// a later import.
pub fn collect_all(conn: &Connection, dek: &[u8; 32]) -> Result<VaultBackup, String> {
    // Credentials
    let mut stmt = conn
        .prepare("SELECT id, service, username, password_encrypted, url, notes, totp_secret, created_at FROM credentials")
        .map_err(|e| e.to_string())?;
    let credentials = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_credentials = Vec::with_capacity(credentials.len());
    for (id, service, username, password, url, notes, totp_secret, created_at) in credentials {
        let at = Place { table: "credentials", id: &id };
        out_credentials.push(BackupCredential {
            service: decrypt_field(dek, &at, "service", &service, "credential name")?,
            username: decrypt_field(dek, &at, "username", &username, "credential username")?,
            password: decrypt_field(dek, &at, "password_encrypted", &password, "credential password")?,
            url: decrypt_field(dek, &at, "url", &url, "credential url")?,
            notes: decrypt_field(dek, &at, "notes", &notes, "credential notes")?,
            totp_secret: decrypt_optional_field(dek, &at, "totp_secret", &totp_secret, "credential 2FA secret")?,
            created_at,
        });
    }

    // Projects
    let mut stmt = conn
        .prepare("SELECT id, name, description, target, methodology, status FROM projects")
        .map_err(|e| e.to_string())?;
    let projects = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    // Entries reference projects by id in the vault and by name in a backup.
    let mut project_names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out_projects = Vec::with_capacity(projects.len());
    for (id, name, description, target, methodology, status) in projects {
        let at = Place { table: "projects", id: &id };
        let name = decrypt_field(dek, &at, "name", &name, "project name")?;
        project_names.insert(id.clone(), name.clone());
        out_projects.push(BackupProject {
            name,
            description: decrypt_field(dek, &at, "description", &description, "project description")?,
            target: decrypt_field(dek, &at, "target", &target, "project target")?,
            methodology: decrypt_field(dek, &at, "methodology", &methodology, "project methodology")?,
            status,
        });
    }

    // Journal entries (with project name for context)
    let mut stmt = conn
        .prepare(
            "SELECT j.id, j.project_id, j.title, j.content, j.entry_type, j.severity, j.created_at
             FROM journal_entries j ORDER BY j.created_at",
        )
        .map_err(|e| e.to_string())?;
    let entries = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_entries = Vec::with_capacity(entries.len());
    for (id, project_id, title, content, entry_type, severity, created_at) in entries {
        let at = Place { table: "journal_entries", id: &id };
        out_entries.push(BackupJournalEntry {
            project_name: project_names.get(&project_id).cloned().unwrap_or_default(),
            title: decrypt_field(dek, &at, "title", &title, "journal title")?,
            content: decrypt_field(dek, &at, "content", &content, "journal content")?,
            entry_type,
            severity,
            created_at,
        });
    }

    // KB entries
    let mut stmt = conn
        .prepare("SELECT id, title, command, description, tags, category FROM kb_entries")
        .map_err(|e| e.to_string())?;
    let kb = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_kb = Vec::with_capacity(kb.len());
    for (id, title, command, description, tags, category) in kb {
        let at = Place { table: "kb_entries", id: &id };
        out_kb.push(BackupKBEntry {
            title: decrypt_field(dek, &at, "title", &title, "command title")?,
            command: decrypt_field(dek, &at, "command", &command, "command body")?,
            description: decrypt_field(dek, &at, "description", &description, "command description")?,
            tags: decrypt_field(dek, &at, "tags", &tags, "command tags")?,
            category,
        });
    }

    let evidence = crate::evidence::backup_records(conn, dek, &project_names)?;

    Ok(VaultBackup {
        version: BACKUP_VERSION.into(),
        credentials: out_credentials,
        projects: out_projects,
        journal_entries: out_entries,
        kb_entries: out_kb,
        evidence,
    })
}

/// Read a field from a 1.0 payload, which carried the source vault's own
/// unbound ciphertext. It only works in the vault that made it.
fn legacy_plaintext(dek: &[u8; 32], value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    vault::decrypt_to_string(dek, value).map_err(|_| {
        format!(
            "{label} cannot be decrypted with this vault's key. This backup was made by a \
             different vault and cannot be restored here — re-export a backup from the \
             vault that produced it."
        )
    })
}

/// Turn a decrypted backup into plain text throughout, ready for
/// `restore_all` to encrypt row by row once each row has its new id.
///
/// Also guarantees that every journal entry references a project that exists in
/// the payload, so the insert cannot violate the foreign key constraint.
pub fn prepare_for_import(mut backup: VaultBackup, dek: &[u8; 32]) -> Result<VaultBackup, String> {
    match backup.version.as_str() {
        BACKUP_VERSION => {} // already plain text inside the encrypted envelope
        LEGACY_BACKUP_VERSION => {
            // 1.0 exported the password in the clear and left every other field
            // as the source vault's ciphertext.
            for cred in &mut backup.credentials {
                cred.username = legacy_plaintext(dek, &cred.username, "credential username")?;
                cred.url = legacy_plaintext(dek, &cred.url, "credential url")?;
                cred.notes = legacy_plaintext(dek, &cred.notes, "credential notes")?;
                if let Some(secret) = &cred.totp_secret {
                    cred.totp_secret = Some(legacy_plaintext(dek, secret, "credential 2FA secret")?);
                }
            }
            for proj in &mut backup.projects {
                proj.description = legacy_plaintext(dek, &proj.description, "project description")?;
                proj.target = legacy_plaintext(dek, &proj.target, "project target")?;
                proj.methodology = legacy_plaintext(dek, &proj.methodology, "project methodology")?;
            }
            for entry in &mut backup.journal_entries {
                entry.title = legacy_plaintext(dek, &entry.title, "journal title")?;
                entry.content = legacy_plaintext(dek, &entry.content, "journal content")?;
            }
            for entry in &mut backup.kb_entries {
                entry.title = legacy_plaintext(dek, &entry.title, "command title")?;
                entry.command = legacy_plaintext(dek, &entry.command, "command body")?;
                entry.description = legacy_plaintext(dek, &entry.description, "command description")?;
                entry.tags = legacy_plaintext(dek, &entry.tags, "command tags")?;
            }
            backup.version = BACKUP_VERSION.into();
        }
        other => {
            return Err(format!(
                "unsupported backup version '{other}' — this file was made by a newer release"
            ));
        }
    }

    ensure_projects_exist(&mut backup);
    Ok(backup)
}

/// Add a placeholder project for any journal entry whose project is missing.
///
/// The payload only references projects by name, so an entry whose project was
/// deleted at the source would otherwise be inserted with a dangling id and
/// abort the whole import on the foreign key constraint.
fn ensure_projects_exist(backup: &mut VaultBackup) {
    let mut known: Vec<String> = backup.projects.iter().map(|p| p.name.clone()).collect();
    let referenced: Vec<String> = backup
        .journal_entries
        .iter()
        .map(|e| e.project_name.clone())
        .chain(backup.evidence.iter().map(|e| e.project_name.clone()))
        .collect();

    for name in referenced {
        if name.is_empty() || known.contains(&name) {
            continue;
        }
        known.push(name.clone());
        backup.projects.push(BackupProject {
            name,
            description: String::new(),
            target: String::new(),
            methodology: String::new(),
            status: "planning".into(),
        });
    }
}

/// Insert a prepared (plain text) backup into the vault atomically, sealing
/// every value to its new row as it goes.
///
/// Every row either lands or none does: a failure part-way through used to leave
/// a half-imported vault behind.
pub fn restore_all(conn: &Connection, dek: &[u8; 32], backup: &VaultBackup) -> Result<(), String> {
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| e.to_string())?;

    let restore = || -> Result<(), String> {
        for cred in &backup.credentials {
            let id = uuid_v4();
            let seal = |column: &str, value: &str| fields::seal(dek, "credentials", &id, column, value);
            let totp = match &cred.totp_secret {
                None => None,
                Some(secret) => Some(seal("totp_secret", secret)?),
            };
            conn.execute(
                "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    seal("service", &cred.service)?,
                    seal("username", &cred.username)?,
                    seal("password_encrypted", &cred.password)?,
                    seal("url", &cred.url)?,
                    seal("notes", &cred.notes)?,
                    totp,
                    cred.created_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        let mut project_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for proj in &backup.projects {
            let pid = uuid_v4();
            project_map.insert(proj.name.clone(), pid.clone());
            let seal = |column: &str, value: &str| fields::seal(dek, "projects", &pid, column, value);
            conn.execute(
                "INSERT INTO projects (id, name, description, target, methodology, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    pid,
                    seal("name", &proj.name)?,
                    seal("description", &proj.description)?,
                    seal("target", &proj.target)?,
                    seal("methodology", &proj.methodology)?,
                    proj.status,
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        for entry in &backup.journal_entries {
            let pid = project_map.get(&entry.project_name).ok_or_else(|| {
                format!(
                    "backup is inconsistent: journal entry '{}' references missing project '{}'",
                    entry.title, entry.project_name
                )
            })?;
            let id = uuid_v4();
            conn.execute(
                "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    id,
                    pid,
                    fields::seal(dek, "journal_entries", &id, "title", &entry.title)?,
                    fields::seal(dek, "journal_entries", &id, "content", &entry.content)?,
                    entry.entry_type,
                    entry.severity,
                    entry.created_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        crate::evidence::restore_records(conn, dek, &project_map, &backup.evidence)?;

        for entry in &backup.kb_entries {
            let id = uuid_v4();
            let seal = |column: &str, value: &str| fields::seal(dek, "kb_entries", &id, column, value);
            conn.execute(
                "INSERT INTO kb_entries (id, title, command, description, tags, category)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    id,
                    seal("title", &entry.title)?,
                    seal("command", &entry.command)?,
                    seal("description", &entry.description)?,
                    seal("tags", &entry.tags)?,
                    entry.category,
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(())
    };

    if let Err(e) = restore() {
        conn.execute("ROLLBACK", []).ok();
        return Err(format!("import failed, no changes were made: {e}"));
    }
    if conn.execute("COMMIT", []).is_err() {
        conn.execute("ROLLBACK", []).ok();
        return Err("import failed to commit, no changes were made".into());
    }

    Ok(())
}