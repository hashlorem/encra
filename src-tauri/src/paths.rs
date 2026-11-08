//! Where the vault lives, and carrying it over from earlier product names.

use std::path::{Path, PathBuf};
use rusqlite::Connection;
use tauri::Manager;

use crate::util::uuid_v4;

pub(crate) const CURRENT_DATABASE_NAME: &str = "encra.db";
/// Earlier product names as (bundle identifier, database file), newest first.
/// Only the first vault found is copied, so an old KeyRPT file can never win
/// over a newer Cobrypt vault.
#[cfg_attr(debug_assertions, allow(dead_code))] // release builds and tests only
pub(crate) const LEGACY_VAULTS: &[(&str, &str)] = &[
    ("com.cobrypt.desktop", "cobrypt.db"),
    ("com.keyrpt.app", "keyrpt.db"),
];

#[cfg_attr(debug_assertions, allow(dead_code))] // release builds and tests only
pub(crate) fn copy_database_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination.parent().ok_or("Encra database path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create Encra data directory: {e}"))?;

    let temp_path = destination.with_extension(format!("db.migrating-{}", uuid_v4()));
    let migration = (|| -> Result<(), String> {
        let source_db = Connection::open_with_flags(
            source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to open previous vault database: {e}"))?;

        source_db.execute(
            "VACUUM INTO ?1",
            rusqlite::params![temp_path.to_string_lossy().as_ref()],
        ).map_err(|e| format!("failed to copy previous vault database: {e}"))?;
        drop(source_db);

        let copied_db = Connection::open_with_flags(
            &temp_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).map_err(|e| format!("failed to validate migrated Encra database: {e}"))?;
        let integrity: String = copied_db
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| format!("failed to check migrated Encra database: {e}"))?;
        drop(copied_db);

        if integrity != "ok" {
            return Err(format!("previous vault database failed integrity check: {integrity}"));
        }

        // A hard link creates the destination atomically and fails if it already
        // exists, so a concurrent startup can never overwrite an Encra vault.
        std::fs::hard_link(&temp_path, destination)
            .map_err(|e| format!("failed to activate migrated Encra database: {e}"))?;
        let _ = std::fs::remove_file(&temp_path);
        Ok(())
    })();

    if migration.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    migration
}

#[cfg_attr(debug_assertions, allow(dead_code))] // release builds and tests only
pub(crate) fn migrate_database_if_needed(current: &Path, candidates: &[PathBuf]) -> Result<bool, String> {
    if current.exists() {
        return Ok(false);
    }

    if let Some(source) = candidates.iter().find(|candidate| candidate.is_file()) {
        copy_database_atomically(source, current)?;
        return Ok(true);
    }

    Ok(false)
}

/// Where an earlier vault may live, in the order it should be preferred: for
/// each old product, a renamed file in this app's own data directory first,
/// then the old app's data directory beside it.
#[cfg_attr(debug_assertions, allow(dead_code))] // release builds and tests only
pub(crate) fn legacy_database_candidates(current_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for (identifier, file) in LEGACY_VAULTS {
        candidates.push(current_dir.join(file));
        if let Some(data_root) = current_dir.parent() {
            candidates.push(data_root.join(identifier).join(file));
        }
    }
    candidates
}

/// Owner-only access to the vault folder (0700) and database (0600), set on
/// every launch. A vault copied in by the brand migration is created with the
/// default 0644, so this fixes it too. SQLite's side files inherit the
/// database's mode, and are covered here in case they already exist.
#[cfg(unix)]
pub(crate) fn restrict_permissions(db_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let set = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("failed to restrict permissions on {}: {e}", path.display()))
    };
    if let Some(dir) = db_path.parent() {
        set(dir, 0o700)?;
    }
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        let path = PathBuf::from(name);
        if path.exists() {
            set(&path, 0o600)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_permissions(_db_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let current_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;

    // Debug builds never open the real vault. ENCRA_DATA_DIR points one at a
    // throwaway folder; without it, a debug build gets its own folder beside
    // the real one and migrates nothing into it. `debug_assertions` is off in
    // release builds, so none of this exists in a shipped app.
    #[cfg(debug_assertions)]
    {
        if let Some(dir) = std::env::var_os("ENCRA_DATA_DIR") {
            return Ok(PathBuf::from(dir).join(CURRENT_DATABASE_NAME));
        }
        let mut dev = current_dir.into_os_string();
        dev.push(".dev");
        Ok(PathBuf::from(dev).join(CURRENT_DATABASE_NAME))
    }

    #[cfg(not(debug_assertions))]
    {
        let current_path = current_dir.join(CURRENT_DATABASE_NAME);
        migrate_database_if_needed(&current_path, &legacy_database_candidates(&current_dir))?;
        Ok(current_path)
    }
}
