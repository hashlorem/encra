//! Files the person picks or drops. Paths come from the system dialog or the
//! window's drop event, both handled in Rust, so the webview never names a
//! path and has no way to read or write a file of its choosing.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager};

/// Files dropped on the window. The page showing claims them shortly after
/// the drop (Evidence or the Nmap parser), or they are forgotten.
#[derive(Default)]
pub(crate) struct DroppedFiles(pub(crate) Mutex<Option<(Instant, Vec<PathBuf>)>>);

pub(crate) const DROP_CLAIM_WINDOW: Duration = Duration::from_secs(30);

/// Keep a drop for the page to claim, and tell the page it happened.
pub(crate) fn window_event(window: &tauri::Window, event: &tauri::WindowEvent) {
    let tauri::WindowEvent::DragDrop(drag) = event else { return };
    match drag {
        tauri::DragDropEvent::Enter { paths, .. } if !paths.is_empty() => {
            let _ = window.emit("files-drag", true);
        }
        tauri::DragDropEvent::Leave => {
            let _ = window.emit("files-drag", false);
        }
        tauri::DragDropEvent::Drop { paths, .. } => {
            let _ = window.emit("files-drag", false);
            if paths.is_empty() {
                return;
            }
            if let Ok(mut dropped) = window.state::<DroppedFiles>().0.lock() {
                *dropped = Some((Instant::now(), paths.clone()));
            }
            let _ = window.emit("files-dropped", paths.len());
        }
        _ => {}
    }
}

/// The files dropped in the last 30 seconds, taken so they are claimed once.
pub(crate) fn take_dropped(app: &tauri::AppHandle) -> Result<Vec<PathBuf>, String> {
    let dropped = app.state::<DroppedFiles>().0.lock().map_err(|e| e.to_string())?.take();
    Ok(match dropped {
        Some((at, paths)) if at.elapsed() < DROP_CLAIM_WINDOW => paths,
        _ => Vec::new(),
    })
}

/// A picked file's name, for messages.
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Read a whole text file, refusing one larger than `max` bytes before
/// reading any of it.
pub(crate) fn read_text_capped(path: &Path, max: u64) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("could not open that file: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("could not open that file: {e}"))?;
    if !meta.is_file() {
        return Err("could not open that file: not a file".into());
    }
    if meta.len() > max {
        return Err(format!("that file is too large ({} bytes, the limit is {max})", meta.len()));
    }
    let mut text = String::with_capacity(meta.len() as usize);
    // The size can change after the check; never read past the limit.
    file.take(max + 1).read_to_string(&mut text).map_err(|e| format!("could not read that file: {e}"))?;
    if text.len() as u64 > max {
        return Err(format!("that file is too large (the limit is {max} bytes)"));
    }
    Ok(text)
}

/// Write `contents` to `dest`, readable by this user only, through a hidden
/// temporary file beside it, so a failed write never leaves half a file.
pub(crate) fn write_private(dest: &Path, contents: &[u8]) -> Result<(), String> {
    let partial = dest.with_file_name(format!(".{}.encra-partial", file_name(dest)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&partial)
            .map_err(|e| format!("could not write that file: {e}"))?;
        file.write_all(contents).map_err(|e| format!("could not write that file: {e}"))?;
        file.sync_all().map_err(|e| format!("could not write that file: {e}"))?;
        std::fs::rename(&partial, dest).map_err(|e| format!("could not write that file: {e}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encra-files-{label}-{}", crate::util::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_read_text_capped_refuses_before_reading() {
        let dir = temp_dir("read");
        let small = dir.join("scan.xml");
        std::fs::write(&small, "<nmaprun/>").unwrap();
        assert_eq!(read_text_capped(&small, 64).unwrap(), "<nmaprun/>");

        // A sparse file: large on paper, so the size check must stop it.
        let big = dir.join("big.xml");
        std::fs::File::create(&big).unwrap().set_len(10 * 1024 * 1024).unwrap();
        assert!(read_text_capped(&big, 1024).unwrap_err().contains("too large"));

        assert!(read_text_capped(&dir.join("missing.xml"), 64).unwrap_err().contains("could not open"));
        assert!(read_text_capped(&dir, 64).is_err(), "a folder is not a file");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_write_private_is_owner_only_and_never_half_written() {
        let dir = temp_dir("write");
        let dest = dir.join("encra-backup.encra");
        std::fs::write(&dest, "old contents").unwrap();
        write_private(&dest, b"new contents").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new contents");
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file left behind");

        let nowhere = dir.join("no-such-folder").join("backup.encra");
        assert!(write_private(&nowhere, b"x").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
