//! Clipboard redirection (MS-RDPECLIP) between the local Wayland/X11 desktop and the session.
//!
//! # Design
//!
//! * [`Clipboard`] owns one worker thread (`bastion-clipboard`) for the whole session, across
//!   reconnects. All clipboard state lives there.
//! * Each connection gets a fresh `CliprdrBackend` from [`Clipboard::backend_factory`]. Its
//!   callbacks run on the session's async thread and only enqueue commands for the worker, so
//!   they never block. The worker answers through the session's `ClipboardMessageProxy`.
//! * The OS side sits behind a small trait (`os::OsClipboard`): Wayland `ext-data-control-v1`
//!   / `wlr-data-control` (via `ironrdp-cliprdr-native`'s data-control client, which runs its
//!   own thread) with an X11/XWayland fallback. Remote data is delay-rendered: nothing crosses
//!   the wire until a local application pastes.
//!
//! # Formats
//!
//! | local                                   | remote                              |
//! |-----------------------------------------|-------------------------------------|
//! | `text/plain;charset=utf-8`, `text/plain`, `UTF8_STRING`, `STRING` | `CF_UNICODETEXT` (`CF_TEXT` in) |
//! | `text/html`                             | `HTML Format` (CF_HTML)             |
//! | `image/png` (+ `image/bmp`, `image/jpeg` out) | `CF_DIBV5`, `CF_DIB`          |
//! | `text/uri-list`, `x-special/gnome-copied-files` | `FileGroupDescriptorW` + FileContents |

mod backend;
mod convert;
mod files;
mod os;
mod uri;
mod worker;

#[cfg(test)]
mod tests;

use core::time::Duration;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;

use anyhow::{Result, anyhow};
use ironrdp_cliprdr::backend::{ClipboardMessageProxy, CliprdrBackendFactory};

use crate::worker::{Command, Config, Worker};

/// How long [`Clipboard::new`] waits for the OS clipboard to open.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long dropping [`Clipboard`] waits for the worker to clean up before detaching it.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct ClipboardOptions {
    /// Allow file copy/paste in both directions.
    pub files: bool,
    /// Hard cap for any single clipboard transfer (one format, or all files of one copy).
    pub max_transfer_bytes: usize,
}

impl Default for ClipboardOptions {
    fn default() -> Self {
        Self { files: true, max_transfer_bytes: 64 * 1024 * 1024 }
    }
}

/// Owns the local clipboard integration for the lifetime of a session (across reconnects).
pub struct Clipboard {
    commands: Sender<Command>,
    opts: ClipboardOptions,
    done: mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Clipboard").field("opts", &self.opts).finish_non_exhaustive()
    }
}

impl Clipboard {
    /// Opens the OS clipboard and starts the clipboard worker. `proxy` receives the CLIPRDR
    /// messages to send; it is called from the worker thread.
    pub fn new(proxy: impl ClipboardMessageProxy + 'static, opts: ClipboardOptions) -> Result<Self> {
        let (commands, receiver) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let events = commands.clone();
        let config = Config::new(opts.files, opts.max_transfer_bytes);
        let thread = std::thread::Builder::new()
            .name("bastion-clipboard".to_owned())
            .spawn(move || {
                let os = match os::open_native(events, config.max_transfer_bytes) {
                    Ok(os) => os,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                Worker::new(os, proxy, config).run(&receiver);
                let _ = done_tx.send(());
                tracing::debug!("Clipboard worker stopped");
            })
            .map_err(|e| anyhow!("cannot start the clipboard thread: {e}"))?;
        match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self { commands, opts, done, thread: Some(thread) }),
            Ok(Err(error)) => Err(anyhow!("local clipboard unavailable: {error}")),
            Err(RecvTimeoutError::Timeout) => Err(anyhow!("local clipboard did not open in time")),
            Err(RecvTimeoutError::Disconnected) => Err(anyhow!("clipboard thread stopped unexpectedly")),
        }
    }

    pub fn backend_factory(&self) -> Box<dyn CliprdrBackendFactory + Send> {
        Box::new(backend::BackendFactory {
            commands: self.commands.clone(),
            files: self.opts.files,
            max_transfer_bytes: self.opts.max_transfer_bytes,
        })
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        // Bounded wait: this may run on an async thread, and the worker could be inside a
        // (timeout-bounded) OS read. If it does not finish in time it cleans up on its own.
        if self.done.recv_timeout(SHUTDOWN_TIMEOUT).is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}
