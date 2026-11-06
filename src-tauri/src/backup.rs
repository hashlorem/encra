use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use crate::util::uuid_v4;
use crate::vault;

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

fn decrypt_field(dek: &[u8; 32], value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    vault::decrypt(dek, value).map_err(|_| {
        format!(
            "failed to decrypt {label} while building the backup — the vault may be corrupted"
        )
    })
}

fn decrypt_optional_field(
    dek: &[u8; 32],
    value: &Option<String>,
    label: &str,
) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(raw) if raw.is_empty() => Ok(Some(String::new())),
        Some(raw) => Ok(Some(decrypt_field(dek, raw, label)?)),
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
        .prepare("SELECT service, username, password_encrypted, url, notes, totp_secret, created_at FROM credentials ORDER BY service")
        .map_err(|e| e.to_string())?;
    let credentials = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_credentials = Vec::with_capacity(credentials.len());
    for (service, username, password, url, notes, totp_secret, created_at) in credentials {
        out_credentials.push(BackupCredential {
            service,
            username: decrypt_field(dek, &username, "credential username")?,
            password: decrypt_field(dek, &password, "credential password")?,
            url: decrypt_field(dek, &url, "credential url")?,
            notes: decrypt_field(dek, &notes, "credential notes")?,
            totp_secret: decrypt_optional_field(dek, &totp_secret, "credential 2FA secret")?,
            created_at,
        });
    }

    // Projects
    let mut stmt = conn
        .prepare("SELECT name, description, target, methodology, status FROM projects ORDER BY name")
        .map_err(|e| e.to_string())?;
    let projects = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_projects = Vec::with_capacity(projects.len());
    for (name, description, target, methodology, status) in projects {
        out_projects.push(BackupProject {
            name,
            description: decrypt_field(dek, &description, "project description")?,
            target: decrypt_field(dek, &target, "project target")?,
            methodology: decrypt_field(dek, &methodology, "project methodology")?,
            status,
        });
    }

    // Journal entries (with project name for context)
    let mut stmt = conn
        .prepare(
            "SELECT p.name, j.title, j.content, j.entry_type, j.severity, j.created_at
             FROM journal_entries j LEFT JOIN projects p ON j.project_id = p.id
             ORDER BY j.created_at",
        )
        .map_err(|e| e.to_string())?;
    let entries = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?.unwrap_or_default(),
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

    let mut out_entries = Vec::with_capacity(entries.len());
    for (project_name, title, content, entry_type, severity, created_at) in entries {
        out_entries.push(BackupJournalEntry {
            project_name,
            title: decrypt_field(dek, &title, "journal title")?,
            content: decrypt_field(dek, &content, "journal content")?,
            entry_type,
            severity,
            created_at,
        });
    }

    // KB entries
    let mut stmt = conn
        .prepare("SELECT title, command, description, tags, category FROM kb_entries ORDER BY title")
        .map_err(|e| e.to_string())?;
    let kb = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut out_kb = Vec::with_capacity(kb.len());
    for (title, command, description, tags, category) in kb {
        out_kb.push(BackupKBEntry {
            title: decrypt_field(dek, &title, "command title")?,
            command: decrypt_field(dek, &command, "command body")?,
            description: decrypt_field(dek, &description, "command description")?,
            tags: decrypt_field(dek, &tags, "command tags")?,
            category,
        });
    }

    Ok(VaultBackup {
        version: BACKUP_VERSION.into(),
        credentials: out_credentials,
        projects: out_projects,
        journal_entries: out_entries,
        kb_entries: out_kb,
    })
}

/// Confirm a field is already ciphertext for this vault, for legacy payloads.
fn require_ciphertext(dek: &[u8; 32], value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    vault::decrypt(dek, value).map(|_| ()).map_err(|_| {
        format!(
            "{label} cannot be decrypted with this vault's key. This backup was made by a \
             different vault and cannot be restored here — re-export a backup from the \
             vault that produced it."
        )
    })
}

/// Turn a decrypted backup into the ciphertext form that `restore_all` stores,
/// using the destination vault's key.
///
/// Also guarantees that every journal entry references a project that exists in
/// the payload, so the insert cannot violate the foreign key constraint.
pub fn prepare_for_import(mut backup: VaultBackup, dek: &[u8; 32]) -> Result<VaultBackup, String> {
    let encrypt = |value: &str| vault::encrypt(dek, value);

    match backup.version.as_str() {
        BACKUP_VERSION => {
            for cred in &mut backup.credentials {
                cred.username = encrypt(&cred.username)?;
                cred.password = encrypt(&cred.password)?;
                cred.url = encrypt(&cred.url)?;
                cred.notes = encrypt(&cred.notes)?;
                cred.totp_secret = match &cred.totp_secret {
                    None => None,
                    Some(secret) => Some(encrypt(secret)?),
                };
            }
            for proj in &mut backup.projects {
                proj.description = encrypt(&proj.description)?;
                proj.target = encrypt(&proj.target)?;
                proj.methodology = encrypt(&proj.methodology)?;
            }
            for entry in &mut backup.journal_entries {
                entry.title = encrypt(&entry.title)?;
                entry.content = encrypt(&entry.content)?;
            }
            for entry in &mut backup.kb_entries {
                entry.title = encrypt(&entry.title)?;
                entry.command = encrypt(&entry.command)?;
                entry.description = encrypt(&entry.description)?;
                entry.tags = encrypt(&entry.tags)?;
            }
        }
        LEGACY_BACKUP_VERSION => {
            // 1.0 exported the password in the clear and left every other field
            // as the source vault's ciphertext. Re-encrypt the password, and
            // verify the rest really is readable with this key rather than
            // writing unreadable bytes back into the vault.
            for cred in &mut backup.credentials {
                cred.password = encrypt(&cred.password)?;
                require_ciphertext(dek, &cred.username, "credential username")?;
                require_ciphertext(dek, &cred.url, "credential url")?;
                require_ciphertext(dek, &cred.notes, "credential notes")?;
                if let Some(secret) = &cred.totp_secret {
                    require_ciphertext(dek, secret, "credential 2FA secret")?;
                }
            }
            for proj in &backup.projects {
                require_ciphertext(dek, &proj.description, "project description")?;
                require_ciphertext(dek, &proj.target, "project target")?;
                require_ciphertext(dek, &proj.methodology, "project methodology")?;
            }
            for entry in &backup.journal_entries {
                require_ciphertext(dek, &entry.title, "journal title")?;
                require_ciphertext(dek, &entry.content, "journal content")?;
            }
            for entry in &backup.kb_entries {
                require_ciphertext(dek, &entry.title, "command title")?;
                require_ciphertext(dek, &entry.command, "command body")?;
                require_ciphertext(dek, &entry.description, "command description")?;
                require_ciphertext(dek, &entry.tags, "command tags")?;
            }
        }
        other => {
            return Err(format!(
                "unsupported backup version '{other}' — this file was made by a newer release"
            ));
        }
    }

    ensure_projects_exist(&mut backup, dek)?;
    Ok(backup)
}

/// Add a placeholder project for any journal entry whose project is missing.
///
/// The payload only references projects by name, so an entry whose project was
/// deleted at the source would otherwise be inserted with a dangling id and
/// abort the whole import on the foreign key constraint.
fn ensure_projects_exist(backup: &mut VaultBackup, dek: &[u8; 32]) -> Result<(), String> {
    let legacy = backup.version == LEGACY_BACKUP_VERSION;
    let blank = |dek: &[u8; 32]| -> Result<String, String> {
        if legacy {
            vault::encrypt(dek, "")
        } else {
            Ok(String::new())
        }
    };

    let mut known: Vec<String> = backup.projects.iter().map(|p| p.name.clone()).collect();
    let referenced: Vec<String> = backup
        .journal_entries
        .iter()
        .map(|e| e.project_name.clone())
        .collect();

    for name in referenced {
        if name.is_empty() || known.contains(&name) {
            continue;
        }
        known.push(name.clone());
        backup.projects.push(BackupProject {
            name,
            description: blank(dek)?,
            target: blank(dek)?,
            methodology: blank(dek)?,
            status: "planning".into(),
        });
    }

    Ok(())
}

/// Insert a prepared (ciphertext) backup into the vault atomically.
///
/// Every row either lands or none does: a failure part-way through used to leave
/// a half-imported vault behind.
pub fn restore_all(conn: &Connection, backup: &VaultBackup) -> Result<(), String> {
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| e.to_string())?;

    let restore = || -> Result<(), String> {
        for cred in &backup.credentials {
            conn.execute(
                "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    uuid_v4(),
                    cred.service,
                    cred.username,
                    cred.password,
                    cred.url,
                    cred.notes,
                    cred.totp_secret,
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
            conn.execute(
                "INSERT INTO projects (id, name, description, target, methodology, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![pid, proj.name, proj.description, proj.target, proj.methodology, proj.status],
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
            conn.execute(
                "INSERT INTO journal_entries (id, project_id, title, content, entry_type, severity, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![uuid_v4(), pid, entry.title, entry.content, entry.entry_type, entry.severity, entry.created_at],
            )
            .map_err(|e| e.to_string())?;
        }

        for entry in &backup.kb_entries {
            conn.execute(
                "INSERT INTO kb_entries (id, title, command, description, tags, category)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![uuid_v4(), entry.title, entry.command, entry.description, entry.tags, entry.category],
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