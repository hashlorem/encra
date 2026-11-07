//! Where the agent socket lives, and who is allowed on the other end of it.
//!
//! The socket sits in /private/tmp/encra-<uid>/ (macOS caps socket paths near
//! 104 bytes, which rules out Application Support). The folder must be ours,
//! a real folder (not a symlink) and 0700; the socket is 0600. A lock file
//! keeps a second Encra from taking the socket over.
//!
//! Both ends check the other: same user, and the same executable, compared by
//! SHA-256. `encra run` is Encra's own binary in another mode, so the peer must
//! be the very file the app is running from. This is best effort against other
//! processes running as the same user (PID reuse is possible), and the
//! approval dialog says so.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub fn default_dir() -> PathBuf {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/private/tmp/encra-{uid}"))
}

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("agent.sock")
}

/// Create the folder, or check an existing one is safe to use.
pub fn prepare_dir(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!("{} is not a plain folder; refusing to use it", dir.display()));
            }
            // SAFETY: getuid cannot fail.
            if meta.uid() != unsafe { libc::getuid() } {
                return Err(format!("{} belongs to another user; refusing to use it", dir.display()));
            }
            if meta.mode() & 0o777 != 0o700 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        Err(_) => {
            std::fs::create_dir(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
        }
    }
}

/// Hold this for as long as the server runs. A second server fails here.
pub fn take_lock(dir: &Path) -> Result<File, String> {
    let file = File::create(dir.join("agent.lock")).map_err(|e| e.to_string())?;
    // SAFETY: a valid, open file descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another Encra is already serving agent requests".into());
    }
    Ok(file)
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| e.to_string())?;
    Ok(hasher.finalize().into())
}

/// SHA-256 of the binary this process runs from, computed once.
pub fn own_executable_hash() -> Result<[u8; 32], String> {
    static HASH: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    HASH.get_or_init(|| {
        let path = std::env::current_exe().map_err(|e| e.to_string())?;
        sha256_file(&path.canonicalize().map_err(|e| e.to_string())?)
    })
    .clone()
}

pub fn pid_path(pid: i32) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is PROC_PIDPATHINFO_MAXSIZE bytes, as proc_pidpath requires.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok().map(PathBuf::from)
}

fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: `info` is a proc_bsdinfo of exactly `size` bytes.
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
    (got == size).then_some(info)
}

/// Up to six ancestors of a process, nearest first, as "name (pid)".
pub fn process_chain(pid: i32) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..6 {
        let Some(info) = bsd_info(current) else { break };
        let parent = info.pbi_ppid as i32;
        if parent <= 1 {
            break;
        }
        let name = pid_path(parent)
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "?".into());
        chain.push(format!("{name} ({parent})"));
        current = parent;
    }
    chain
}

pub struct Peer {
    pub pid: i32,
}

/// Check the other end of a connection: same user, same executable.
pub fn verify_peer(stream: &UnixStream) -> Result<Peer, String> {
    let fd = stream.as_raw_fd();
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: valid socket and out-pointers.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != unsafe { libc::getuid() } {
        return Err("caller is not running as you".into());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: valid socket; `pid` is a pid_t and `len` its size.
    let got = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&mut pid as *mut libc::pid_t).cast(), &mut len) };
    if got != 0 || pid <= 0 {
        return Err("could not identify the caller".into());
    }
    let path = pid_path(pid).ok_or("could not find the caller's executable")?;
    if sha256_file(&path)? != own_executable_hash()? {
        return Err(format!("caller {} is not this Encra's own binary", path.display()));
    }
    Ok(Peer { pid })
}

/// Interpreters that run code given inline on the command line. Such a
/// request can do anything with a secret, so the dialog flags it in red.
pub fn is_inline_script(argv: &[String]) -> bool {
    const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "fish", "ksh", "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "osascript", "pwsh"];
    let Some(first) = argv.first() else { return false };
    let name = Path::new(first).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let is_interpreter = INTERPRETERS.iter().any(|i| name == *i || name.starts_with(&format!("{i}.")) || (name.starts_with("python3") && *i == "python3"));
    // Short flags can be clustered ("-lc", "-ne"), so look inside the cluster.
    // Flagging too much here is the safe direction.
    let inline_flag = |arg: &String| {
        matches!(arg.as_str(), "--eval" | "-Command")
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].chars().any(|c| c == 'c' || c == 'e'))
    };
    is_interpreter && argv.iter().skip(1).any(inline_flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("encra-sock-{label}-{}", crate::util::uuid_v4()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn test_prepare_dir_creates_0700_and_refuses_symlinks() {
        let base = temp("dir");
        let dir = base.join("agent");
        prepare_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);

        // An existing loose folder is tightened.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);

        // A symlink planted where the folder should be is refused.
        let link = base.join("planted");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(prepare_dir(&link).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_second_server_cannot_take_the_lock() {
        let dir = temp("lock");
        let first = take_lock(&dir).unwrap();
        assert!(take_lock(&dir).is_err());
        drop(first);
        assert!(take_lock(&dir).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_inline_scripts_are_recognised() {
        let argv = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_inline_script(&argv(&["/bin/sh", "-c", "echo $TOKEN"])));
        assert!(is_inline_script(&argv(&["bash", "-lc", "env"])));
        assert!(is_inline_script(&argv(&["/opt/homebrew/bin/python3.12", "-c", "import os"])));
        assert!(is_inline_script(&argv(&["node", "-e", "console.log(process.env)"])));
        assert!(!is_inline_script(&argv(&["/bin/sh", "./deploy.sh"])));
        assert!(!is_inline_script(&argv(&["/usr/bin/curl", "-c", "cookies.txt"])));
        assert!(!is_inline_script(&[]));
    }
}
