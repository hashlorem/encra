//! The socket server inside the app, and the queue of requests waiting for
//! a person to decide.
//!
//! A request is answered only by an explicit decision (approve, deny), or ends
//! with no secret sent: timeout, the caller disconnecting, the vault sealing,
//! or agent access being turned off.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use super::protocol::{self, Request, Response};
use super::{refs, sock};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// What the approval dialog shows. Never a value.
#[derive(Debug, Clone, Serialize)]
pub struct PendingInfo {
    pub id: String,
    pub agent: String,
    pub argv: Vec<String>,
    pub executable: String,
    pub cwd: String,
    pub references: Vec<String>,
    /// The caller's parent processes, nearest first.
    pub chain: Vec<String>,
    pub inline_script: bool,
}

pub enum Decision {
    Approve(Vec<(String, Zeroizing<Vec<u8>>)>),
    Deny,
    Fail(String),
}

struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket: PathBuf,
    _lock: File,
}

type Notify = Box<dyn Fn() + Send + Sync>;
type Log = Box<dyn Fn(&str, &str) + Send + Sync>;

pub struct Hub {
    pending: Mutex<HashMap<String, (PendingInfo, Sender<Decision>)>>,
    server: Mutex<Option<Server>>,
    /// Tell the UI a request arrived (bring the window forward).
    notify: Notify,
    /// Best-effort activity log entry: (action, detail).
    log: Log,
    timeout: Duration,
}

impl Hub {
    pub fn new(notify: Notify, log: Log, timeout: Duration) -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(HashMap::new()), server: Mutex::new(None), notify, log, timeout })
    }

    pub fn is_running(&self) -> bool {
        self.server.lock().map(|s| s.is_some()).unwrap_or(false)
    }

    pub fn start(self: &Arc<Self>, dir: &Path) -> Result<(), String> {
        let mut server = self.server.lock().map_err(|e| e.to_string())?;
        if server.is_some() {
            return Ok(());
        }
        sock::prepare_dir(dir)?;
        let lock = sock::take_lock(dir)?;
        let socket = sock::socket_path(dir);
        // Safe to remove: we hold the lock, so no live server owns it.
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).map_err(|e| format!("could not open the agent socket: {e}"))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;

        let stop = Arc::new(AtomicBool::new(false));
        let hub = Arc::clone(self);
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let hub = Arc::clone(&hub);
                        std::thread::spawn(move || hub.handle(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => std::thread::sleep(Duration::from_millis(250)),
                }
            }
        });
        *server = Some(Server { stop, thread: Some(thread), socket, _lock: lock });
        Ok(())
    }

    /// Stop listening and end every waiting request with no secret sent.
    pub fn stop(&self) {
        if let Ok(mut server) = self.server.lock() {
            if let Some(mut running) = server.take() {
                running.stop.store(true, Ordering::SeqCst);
                if let Some(thread) = running.thread.take() {
                    let _ = thread.join();
                }
                let _ = std::fs::remove_file(&running.socket);
            }
        }
        self.cancel_all("agent access was turned off");
    }

    pub fn pending(&self) -> Vec<PendingInfo> {
        self.pending.lock().map(|p| p.values().map(|(info, _)| info.clone()).collect()).unwrap_or_default()
    }

    /// Remove a request so exactly one decision can be made on it.
    pub fn take(&self, id: &str) -> Option<(PendingInfo, Sender<Decision>)> {
        self.pending.lock().ok()?.remove(id)
    }

    /// End every waiting request without a secret (on seal, or turning off).
    pub fn cancel_all(&self, reason: &str) {
        let drained: Vec<_> = self.pending.lock().map(|mut p| p.drain().collect()).unwrap_or_default();
        for (_, (_, tx)) in drained {
            let _ = tx.send(Decision::Fail(reason.to_string()));
        }
    }

    fn handle(self: Arc<Self>, mut stream: UnixStream) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let peer = match sock::verify_peer(&stream) {
            Ok(peer) => peer,
            Err(reason) => {
                (self.log)("agent_refused", &format!("refused a connection: {reason}"));
                let _ = protocol::write_response(&mut stream, &Response::Error(reason));
                return;
            }
        };
        let request = match protocol::read_request(&mut stream).and_then(validate) {
            Ok(request) => request,
            Err(reason) => {
                let _ = protocol::write_response(&mut stream, &Response::Error(reason));
                return;
            }
        };

        let id = crate::util::uuid_v4();
        let info = PendingInfo {
            id: id.clone(),
            inline_script: sock::is_inline_script(&request.argv),
            chain: sock::process_chain(peer.pid),
            agent: request.agent,
            argv: request.argv,
            executable: request.executable,
            cwd: request.cwd,
            references: request.references,
        };
        // Names stay out of the log (it is readable while sealed): fields only.
        let fields: Vec<&str> = info.references.iter().filter_map(|r| refs::parse(r).ok()).map(|r| refs::field_name(r.field)).collect();
        (self.log)("agent_request", &format!("{} asked for {} to run {} in {}", info.agent, fields.join(", "), info.executable, info.cwd));

        let (tx, rx) = mpsc::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id.clone(), (info, tx));
        }
        (self.notify)();

        let started = Instant::now();
        let response = loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Decision::Approve(values)) => break Response::Approved(values),
                Ok(Decision::Deny) => break Response::Denied,
                Ok(Decision::Fail(reason)) => break Response::Error(reason),
                Err(RecvTimeoutError::Disconnected) => break Response::Error("request cancelled".into()),
                Err(RecvTimeoutError::Timeout) => {
                    if started.elapsed() >= self.timeout {
                        if self.take(&id).is_some() {
                            (self.log)("agent_timeout", "request expired with no answer");
                        }
                        break Response::Error("no answer in time".into());
                    }
                    if caller_gone(&stream) && self.take(&id).is_some() {
                        (self.log)("agent_cancelled", "caller disconnected before an answer");
                        return;
                    }
                }
            }
        };
        let _ = protocol::write_response(&mut stream, &response);
    }
}

fn validate(request: Request) -> Result<Request, String> {
    if request.argv.is_empty() || !request.executable.starts_with('/') || !request.cwd.starts_with('/') {
        return Err("malformed request".into());
    }
    if request.references.is_empty() || request.references.len() > 64 {
        return Err("a request must name between 1 and 64 references".into());
    }
    for reference in &request.references {
        refs::parse(reference)?;
    }
    // The name lands in the activity log; a newline could forge a line.
    if request.agent.chars().count() > 64 || request.agent.chars().any(char::is_control) {
        return Err("agent name must be under 64 characters with no control characters".into());
    }
    Ok(request)
}

/// Whether the caller hung up or sent anything more, either of which cancels
/// the request. Peeks without consuming.
fn caller_gone(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut byte = [0u8; 1];
    // SAFETY: valid socket, one-byte buffer; MSG_PEEK leaves the data queued.
    let got = unsafe { libc::recv(stream.as_raw_fd(), byte.as_mut_ptr().cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    let quiet = got < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock;
    !quiet
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop();
    }
}
