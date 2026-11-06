use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KBEntry {
    pub id: String,
    pub title: String,
    pub command: String,
    pub description: String,
    pub tags: String,
    pub category: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct KBInput {
    pub title: String,
    pub command: String,
    pub description: String,
    pub tags: String,
    pub category: String,
}

pub fn init_kb_tables(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS kb_entries (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            command TEXT DEFAULT '',
            description TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            category TEXT DEFAULT 'general',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .map_err(|e| e.to_string())
}
