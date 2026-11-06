use rusqlite::Connection;
use serde::{Deserialize, Serialize};

// --- Models ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: String,
    pub target: String,
    pub methodology: String,
    pub status: String, // planning, in_progress, completed
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JournalEntry {
    pub id: String,
    pub project_id: String,
    pub title: String,
    pub content: String,
    pub entry_type: String, // finding, recon, exploitation, post_exploit, note, remediation
    pub severity: String,   // critical, high, medium, low, info
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ProjectInput {
    pub name: String,
    pub description: String,
    pub target: String,
    pub methodology: String,
}

#[derive(Debug, Deserialize)]
pub struct EntryInput {
    pub project_id: String,
    pub title: String,
    pub content: String,
    pub entry_type: String,
    pub severity: String,
}

// --- DB Init ---

pub fn init_journal_tables(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            target TEXT DEFAULT '',
            methodology TEXT DEFAULT '',
            status TEXT DEFAULT 'planning',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS journal_entries (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            entry_type TEXT DEFAULT 'note',
            severity TEXT DEFAULT 'info',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        ",
    )
    .map_err(|e| e.to_string())
}
