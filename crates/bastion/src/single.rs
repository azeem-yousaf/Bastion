//! Single-instance guard: launching Bastion while it is already running (usually hidden in the
//! system tray) shows the running instance's main window instead of starting a second process.
//!
//! The first process takes an exclusive `flock` on `bastion.lock` in `$XDG_RUNTIME_DIR` and
//! listens on `bastion.sock` next to it. A later launch finds the lock held, sends its request
//! (the launcher's activation token and an optional `.rdp` file to import) over the socket and
//! exits. The lock, not the socket file, decides who is first, so a socket left behind by a
//! crash is simply replaced.
//!
//! The runtime directory is private to the user (0700); the listener additionally refuses
//! connections from any other uid, bounds the message size and never blocks on a slow client
//! for more than a couple of seconds. A forwarded file goes through the same import-and-review
//! path as one given on the command line — nothing connects by itself.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LOCK_NAME: &str = "bastion.lock";
const SOCKET_NAME: &str = "bastion.sock";
/// Largest request accepted: a token plus a path (`PATH_MAX` is 4096).
const MAX_MESSAGE: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACK: &[u8] = b"ok";

/// What a launch asks the running instance to do. Showing the main window is implied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// The launcher's activation token (`XDG_ACTIVATION_TOKEN`), which lets the compositor
    /// give the window focus.
    pub token: Option<String>,
    /// A `.rdp` file to import (absolute path).
    pub import: Option<PathBuf>,
}

impl Request {
    /// The request for this process: the activation token from the environment and `import`
    /// made absolute (the running instance may have a different working directory).
    pub fn from_launch(import: Option<&Path>) -> Self {
        let token = ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"]
            .iter()
            .find_map(|k| std::env::var(k).ok())
            .filter(|t| !t.is_empty());
        let import = import.map(|p| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()));
        Self { token, import }
    }

    /// `token NUL path`; either part may be empty.
    fn encode(&self) -> Vec<u8> {
        let mut out = self.token.as_deref().unwrap_or("").as_bytes().to_vec();
        out.push(0);
        if let Some(p) = &self.import {
            out.extend_from_slice(p.as_os_str().as_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_MESSAGE {
            return None;
        }
        let split = bytes.iter().position(|b| *b == 0)?;
        let (token, path) = (&bytes[..split], &bytes[split + 1..]);
        // A token is an opaque printable string; anything else is dropped rather than passed on.
        let token = std::str::from_utf8(token)
            .ok()
            .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_graphic()))
            .map(str::to_owned);
        let import = (!path.is_empty() && !path.contains(&0))
            .then(|| PathBuf::from(OsString::from_vec(path.to_vec())))
            .filter(|p| p.is_absolute());
        Some(Self { token, import })
    }
}

/// The first instance: holds the lock and the listening socket.
#[derive(Debug)]
pub struct Primary {
    listener: UnixListener,
    _lock: File,
}

#[derive(Debug)]
pub enum Startup {
    /// No other instance is running; this process should start normally and [`Primary::serve`].
    Primary(Primary),
    /// A running instance took the request; this process should exit.
    Forwarded,
}

/// The user's private runtime directory, or `None` when there is none we can trust (then
/// Bastion simply starts without the single-instance guard).
pub fn runtime_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty())?);
    let meta = std::fs::metadata(&dir).ok()?;
    let ours = meta.uid() == unsafe { libc::geteuid() };
    (dir.is_absolute() && meta.is_dir() && ours && meta.permissions().mode() & 0o077 == 0).then_some(dir)
}

/// Becomes the primary instance in `dir`, or hands `request` to the one already running.
pub fn acquire(dir: &Path, request: &Request) -> io::Result<Startup> {
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LOCK_NAME))?;
    let socket = dir.join(SOCKET_NAME);
    match lock.try_lock() {
        Ok(()) => {
            // We hold the lock, so any socket here is a leftover from a crashed instance.
            match std::fs::remove_file(&socket) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
            let listener = UnixListener::bind(&socket)?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
            Ok(Startup::Primary(Primary { listener, _lock: lock }))
        }
        Err(std::fs::TryLockError::WouldBlock) => forward(&socket, request).map(|()| Startup::Forwarded),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// Sends `request` to the running instance and waits for its acknowledgement.
fn forward(socket: &Path, request: &Request) -> io::Result<()> {
    // The other process may have taken the lock a moment ago and not bound the socket yet.
    let mut attempt = 0;
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) if attempt >= 20 => return Err(e),
            Err(_) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&request.encode())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut ack = [0u8; ACK.len()];
    match stream.read_exact(&mut ack) {
        Ok(()) if ack == ACK => Ok(()),
        Ok(()) => Err(io::Error::other("unexpected reply from the running instance")),
        // Connected and sent, but no answer yet: the running instance is still starting up (or
        // busy) and will read the request from the socket's queue when it gets there. Starting
        // a second instance now would handle the request twice.
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(()),
        Err(e) => Err(e),
    }
}

impl Primary {
    /// Handles launch requests on a background thread for the rest of the process's life.
    /// Call it as soon as possible after [`acquire`]: until then, later launches wait.
    pub fn serve(self, on_request: impl Fn(Request) + Send + 'static) {
        let spawned = std::thread::Builder::new().name("bastion-instance".into()).spawn(move || {
            // Move the whole guard in (not just the listener): the lock must be held for as
            // long as the process lives.
            let Self { listener, _lock } = self;
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if let Some(request) = receive(stream) {
                            on_request(request);
                        }
                    }
                    // E.g. out of file descriptors: do not spin.
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
        });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "Could not start the single-instance listener");
        }
    }
}

/// Reads one request from a connection; `None` for anything not from this user or malformed.
fn receive(mut stream: UnixStream) -> Option<Request> {
    if peer_uid(&stream)? != unsafe { libc::geteuid() } {
        return None;
    }
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let mut bytes = Vec::new();
    (&mut stream).take(MAX_MESSAGE as u64 + 1).read_to_end(&mut bytes).ok()?;
    let request = Request::decode(&bytes)?;
    // The launcher only needs to know the request arrived; ignore a client that went away.
    let _ = stream.write_all(ACK);
    Some(request)
}

fn peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
    let mut cred = libc::ucred { pid: 0, uid: libc::uid_t::MAX, gid: libc::gid_t::MAX };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes and `len` is the size of `cred`.
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &raw mut len)
    };
    (rc == 0 && len as usize == size_of::<libc::ucred>()).then_some(cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn primary(dir: &Path) -> Primary {
        match acquire(dir, &Request::default()).unwrap() {
            Startup::Primary(p) => p,
            Startup::Forwarded => panic!("expected to be the first instance"),
        }
    }

    #[test]
    fn second_launch_is_forwarded_to_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        primary(dir.path()).serve(move |r| {
            let _ = tx.send(r);
        });

        let request = Request { token: Some("token-123".into()), import: Some("/home/u/Work PC.rdp".into()) };
        assert!(matches!(acquire(dir.path(), &request).unwrap(), Startup::Forwarded));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), request);

        // A plain launch (icon click) just asks for the window.
        assert!(matches!(acquire(dir.path(), &Request::default()).unwrap(), Startup::Forwarded));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Request::default());
    }

    #[test]
    fn a_launch_while_the_first_is_still_starting_is_queued_not_duplicated() {
        let dir = tempfile::tempdir().unwrap();
        // The first instance holds the lock and the socket but is not serving yet (slow start).
        let first = primary(dir.path());
        let request = Request { token: None, import: Some("/home/u/a.rdp".into()) };
        let started = std::time::Instant::now();
        assert!(matches!(acquire(dir.path(), &request).unwrap(), Startup::Forwarded));
        assert!(started.elapsed() < IO_TIMEOUT * 2);
        // Once it serves, the queued request is delivered.
        let (tx, rx) = mpsc::channel();
        first.serve(move |r| {
            let _ = tx.send(r);
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), request);
    }

    #[test]
    fn a_crashed_instance_leaves_no_obstacle() {
        let dir = tempfile::tempdir().unwrap();
        let first = primary(dir.path());
        // Dropping releases the lock (as process exit does) but leaves the socket file behind.
        drop(first);
        assert!(dir.path().join(SOCKET_NAME).exists());
        let second = primary(dir.path());
        let mode = std::fs::metadata(dir.path().join(SOCKET_NAME)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(second);
    }

    #[test]
    fn lock_file_is_never_opened_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("victim");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_NAME)).unwrap();
        assert!(acquire(dir.path(), &Request::default()).is_err());
    }

    #[test]
    fn requests_round_trip_and_hostile_ones_are_neutralised() {
        for r in [
            Request::default(),
            Request { token: Some("abc_DEF-1".into()), import: None },
            Request { token: None, import: Some("/tmp/a b/é.rdp".into()) },
        ] {
            assert_eq!(Request::decode(&r.encode()), Some(r));
        }
        // No separator, or too large: rejected outright.
        assert_eq!(Request::decode(b"no separator"), None);
        assert_eq!(Request::decode(&vec![0u8; MAX_MESSAGE + 1]), None);
        // Relative paths, embedded NULs and non-printable tokens are dropped.
        assert_eq!(Request::decode(b"\0relative.rdp"), Some(Request::default()));
        assert_eq!(Request::decode(b"\0/a\0/b"), Some(Request::default()));
        assert_eq!(Request::decode(b"bad token\n\0"), Some(Request::default()));
    }

    #[test]
    fn oversized_or_silent_clients_do_not_reach_the_app() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        primary(dir.path()).serve(move |r| {
            let _ = tx.send(r);
        });
        let mut big = UnixStream::connect(dir.path().join(SOCKET_NAME)).unwrap();
        let _ = big.write_all(&vec![b'a'; MAX_MESSAGE * 2]);
        drop(big);
        // The listener is still alive and serves the next launch.
        assert!(matches!(acquire(dir.path(), &Request::default()).unwrap(), Startup::Forwarded));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Request::default());
        assert!(rx.try_recv().is_err());
    }
}
