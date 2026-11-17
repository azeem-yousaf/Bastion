//! The OS clipboard abstraction used by the protocol worker.
//!
//! Real implementations: Wayland data-control ([`wayland`]) with an X11/XWayland fallback
//! ([`x11`]). Tests use an in-memory fake implementing [`OsClipboard`].
//!
//! Implementations report asynchronous events (another client changed the selection, a local
//! application pastes something we advertised) by sending [`Command::LocalChanged`] /
//! [`Command::Paste`] into the worker's command channel.

pub(crate) mod wayland;
pub(crate) mod x11;

use std::sync::mpsc::Sender;

use crate::worker::Command;

type CompletePaste = Box<dyn FnOnce(Option<Vec<u8>>) + Send>;

/// A delayed-rendering paste from a local application. Every completion path, including being
/// dropped, answers the paste exactly once (dropping = failure).
pub(crate) struct Transfer {
    mime: String,
    generation: u64,
    complete: Option<CompletePaste>,
}

impl core::fmt::Debug for Transfer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transfer")
            .field("mime", &self.mime)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Transfer {
    pub(crate) fn new(mime: String, generation: u64, complete: impl FnOnce(Option<Vec<u8>>) + Send + 'static) -> Self {
        Self { mime, generation, complete: Some(Box::new(complete)) }
    }

    pub(crate) fn mime_type(&self) -> &str {
        &self.mime
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn finish(mut self, data: Option<Vec<u8>>) {
        if let Some(complete) = self.complete.take() {
            complete(data);
        }
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if let Some(complete) = self.complete.take() {
            complete(None);
        }
    }
}

/// One MIME type to put on the local clipboard: with data now, or delay-rendered (`None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OfferItem {
    pub(crate) mime: String,
    pub(crate) data: Option<Vec<u8>>,
}

impl OfferItem {
    pub(crate) fn delayed(mime: &str) -> Self {
        Self { mime: mime.to_owned(), data: None }
    }
}

/// The local clipboard as seen by the worker. All methods are called on the worker thread and
/// may block briefly (reads are bounded by the implementation's own timeouts).
pub(crate) trait OsClipboard: Send {
    /// Whether the current selection is ours.
    fn is_owner(&self) -> bool;
    /// MIME types offered by the current selection (empty if none).
    fn mime_types(&self) -> Vec<String>;
    /// Reads the selection as `mime`. `Ok(None)` if not offered.
    fn read(&mut self, mime: &str) -> Result<Option<Vec<u8>>, String>;
    /// Takes ownership of the selection, offering `items`. Delayed items raise
    /// [`Command::Paste`] carrying `generation`.
    fn offer(&mut self, items: &[OfferItem], generation: u64) -> Result<(), String>;
    /// Gives up the selection if we own it.
    fn clear(&mut self);
}

/// Opens Wayland data-control, falling back to X11.
pub(crate) fn open_native(events: Sender<Command>, max_read_bytes: usize) -> Result<Box<dyn OsClipboard>, String> {
    match wayland::WaylandClipboard::open(events.clone(), max_read_bytes) {
        Ok(c) => {
            tracing::info!(protocol = %c.protocol(), "Clipboard: using Wayland data-control");
            Ok(Box::new(c))
        }
        Err(wayland_error) => {
            tracing::debug!(%wayland_error, "Wayland data-control unavailable; trying X11");
            x11::X11Clipboard::open(events, max_read_bytes)
                .map(|c| {
                    tracing::info!("Clipboard: using X11 selections");
                    Box::new(c) as Box<dyn OsClipboard>
                })
                .map_err(|x11_error| format!("Wayland: {wayland_error}; X11: {x11_error}"))
        }
    }
}

impl OsClipboard for Box<dyn OsClipboard> {
    fn is_owner(&self) -> bool {
        (**self).is_owner()
    }
    fn mime_types(&self) -> Vec<String> {
        (**self).mime_types()
    }
    fn read(&mut self, mime: &str) -> Result<Option<Vec<u8>>, String> {
        (**self).read(mime)
    }
    fn offer(&mut self, items: &[OfferItem], generation: u64) -> Result<(), String> {
        (**self).offer(items, generation)
    }
    fn clear(&mut self) {
        (**self).clear();
    }
}
