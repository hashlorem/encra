//! Copying secrets from Rust, and wiping them again.
//!
//! The webview used to receive every secret so it could call
//! `navigator.clipboard`. Copying here means a vault value goes straight from
//! the database to the pasteboard. On macOS the entry is marked
//! `org.nspasteboard.ConcealedType`, which clipboard managers honour by not
//! recording it.
//!
//! A wipe only clears the clipboard if it still holds what Encra put there,
//! so it never erases something the user copied from another app since.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::util::constant_time_eq;

/// How long a copied value stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

pub trait ClipboardBackend: Send + Sync {
    fn write(&self, text: &str) -> Result<(), String>;
    /// The current clipboard text, or `None` if it holds no text.
    fn read(&self) -> Option<String>;
    fn clear(&self) -> Result<(), String>;
}

/// The real pasteboard. A fresh handle per call is cheap on macOS and avoids
/// holding one across threads.
pub struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn write(&self, text: &str) -> Result<(), String> {
        let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
        #[cfg(target_os = "macos")]
        {
            use arboard::SetExtApple;
            clipboard.set().exclude_from_history().text(text).map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "macos"))]
        {
            clipboard.set_text(text).map_err(|e| e.to_string())
        }
    }

    fn read(&self) -> Option<String> {
        arboard::Clipboard::new().ok()?.get_text().ok()
    }

    fn clear(&self) -> Result<(), String> {
        arboard::Clipboard::new().map_err(|e| e.to_string())?.clear().map_err(|e| e.to_string())
    }
}

#[derive(Default)]
struct Pending {
    /// Bumped on every copy, so an older timer knows it has been superseded.
    generation: u64,
    /// Hash of the value Encra last wrote, while a wipe is still owed.
    digest: Option<[u8; 32]>,
}

pub struct ClipboardGuard {
    backend: Box<dyn ClipboardBackend>,
    pending: Mutex<Pending>,
    clear_after: Duration,
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

impl ClipboardGuard {
    pub fn new(backend: Box<dyn ClipboardBackend>, clear_after: Duration) -> Arc<Self> {
        Arc::new(Self { backend, pending: Mutex::new(Pending::default()), clear_after })
    }

    pub fn system() -> Arc<Self> {
        Self::new(Box::new(SystemClipboard), CLEAR_AFTER)
    }

    /// Write `text` and schedule its wipe, replacing any earlier pending wipe.
    pub fn copy(self: &Arc<Self>, text: &str) -> Result<(), String> {
        self.backend.write(text)?;
        let generation = {
            let mut pending = self.pending.lock().map_err(|e| e.to_string())?;
            pending.generation += 1;
            pending.digest = Some(digest(text));
            pending.generation
        };
        let guard = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(guard.clear_after);
            guard.wipe_if_current(Some(generation));
        });
        Ok(())
    }

    /// Wipe now if a copied value is still owed a wipe. Called on every lock.
    /// Returns whether the clipboard was cleared.
    pub fn wipe_now(&self) -> bool {
        self.wipe_if_current(None)
    }

    fn wipe_if_current(&self, generation: Option<u64>) -> bool {
        let Ok(mut pending) = self.pending.lock() else { return false };
        if generation.is_some_and(|g| g != pending.generation) {
            return false;
        }
        let Some(expected) = pending.digest.take() else { return false };
        let still_ours = self
            .backend
            .read()
            .is_some_and(|current| constant_time_eq(&digest(&current), &expected));
        still_ours && self.backend.clear().is_ok()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// An in-memory clipboard, so tests never touch the real one.
    #[derive(Default)]
    pub struct FakeClipboard(pub Mutex<Option<String>>);

    impl ClipboardBackend for Arc<FakeClipboard> {
        fn write(&self, text: &str) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(text.to_string());
            Ok(())
        }
        fn read(&self) -> Option<String> {
            self.0.lock().unwrap().clone()
        }
        fn clear(&self) -> Result<(), String> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn guard(clear_after: Duration) -> (Arc<ClipboardGuard>, Arc<FakeClipboard>) {
        let fake = Arc::new(FakeClipboard::default());
        (ClipboardGuard::new(Box::new(Arc::clone(&fake)), clear_after), fake)
    }

    fn contents(fake: &FakeClipboard) -> Option<String> {
        fake.0.lock().unwrap().clone()
    }

    #[test]
    fn test_copy_is_wiped_after_the_delay() {
        let (guard, fake) = guard(Duration::from_millis(30));
        guard.copy("s3cret-value").unwrap();
        assert_eq!(contents(&fake).as_deref(), Some("s3cret-value"));
        thread::sleep(Duration::from_millis(200));
        assert_eq!(contents(&fake), None);
    }

    #[test]
    fn test_wipe_leaves_something_the_user_copied_since() {
        let (guard, fake) = guard(Duration::from_millis(30));
        guard.copy("s3cret-value").unwrap();
        *fake.0.lock().unwrap() = Some("copied from another app".into());
        thread::sleep(Duration::from_millis(200));
        assert_eq!(contents(&fake).as_deref(), Some("copied from another app"));
    }

    #[test]
    fn test_a_newer_copy_is_not_wiped_by_the_older_timer() {
        let (guard, fake) = guard(Duration::from_millis(150));
        guard.copy("first").unwrap();
        thread::sleep(Duration::from_millis(100));
        guard.copy("second").unwrap();
        // The first timer fires around 150ms; the second is owed until ~250ms.
        thread::sleep(Duration::from_millis(90));
        assert_eq!(contents(&fake).as_deref(), Some("second"), "older timer must not clear a newer copy");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(contents(&fake), None);
    }

    #[test]
    fn test_wipe_now_on_lock_clears_a_pending_copy_once() {
        let (guard, fake) = guard(Duration::from_secs(60));
        guard.copy("s3cret-value").unwrap();
        assert!(guard.wipe_now());
        assert_eq!(contents(&fake), None);
        // Nothing owed any more, so a second lock leaves new contents alone.
        *fake.0.lock().unwrap() = Some("later".into());
        assert!(!guard.wipe_now());
        assert_eq!(contents(&fake).as_deref(), Some("later"));
    }

    #[test]
    fn test_wipe_now_with_nothing_copied_does_nothing() {
        let (guard, fake) = guard(Duration::from_secs(60));
        *fake.0.lock().unwrap() = Some("unrelated".into());
        assert!(!guard.wipe_now());
        assert_eq!(contents(&fake).as_deref(), Some("unrelated"));
    }
}
