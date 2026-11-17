//! Wayland clipboard through `ext-data-control-v1` / `wlr-data-control-unstable-v1`, using the
//! data-control client from `ironrdp-cliprdr-native`.
//!
//! The data-control client marks our own selections, so `on_change` only fires for other
//! clients' copies (no echo of our own offers). It owns its own thread; pastes of delayed types
//! arrive as [`TransferRequest`]s which we forward to the worker as [`Transfer`]s. A paste not
//! answered within 5 s is closed by data-control, but a late answer is cached and serves the
//! next paste of that type.

use std::sync::mpsc::Sender;

use ironrdp_cliprdr_native::data_control::{Content, DataControl, Options, Protocol, TransferRequest};

use super::{OfferItem, OsClipboard, Transfer};
use crate::worker::Command;

pub(crate) struct WaylandClipboard {
    clipboard: DataControl,
    events: Sender<Command>,
}

impl WaylandClipboard {
    pub(crate) fn open(events: Sender<Command>, max_read_bytes: usize) -> Result<Self, String> {
        let clipboard = DataControl::connect_with(&Options::new().max_read_bytes(max_read_bytes.max(1024)))
            .map_err(|e| e.to_string())?;
        let changes = events.clone();
        clipboard.on_change(move |_| {
            let _ = changes.send(Command::LocalChanged);
        });
        Ok(Self { clipboard, events })
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.clipboard.protocol()
    }
}

fn answer(request: TransferRequest, data: Option<Vec<u8>>) {
    let result = match data {
        Some(data) => request.complete(data),
        None => request.fail(),
    };
    if let Err(error) = result {
        tracing::debug!(%error, "Could not finish a Wayland paste");
    }
}

impl OsClipboard for WaylandClipboard {
    fn is_owner(&self) -> bool {
        self.clipboard.owns_selection()
    }

    fn mime_types(&self) -> Vec<String> {
        self.clipboard.selection_mime_types()
    }

    fn read(&mut self, mime: &str) -> Result<Option<Vec<u8>>, String> {
        self.clipboard.read(mime).map_err(|e| e.to_string())
    }

    fn offer(&mut self, items: &[OfferItem], generation: u64) -> Result<(), String> {
        let events = self.events.clone();
        self.clipboard.on_transfer(move |request| {
            let mime = request.mime_type().to_owned();
            let transfer = Transfer::new(mime, generation, move |data| answer(request, data));
            // If the worker is gone the transfer is dropped here, which fails the paste.
            let _ = events.send(Command::Paste(transfer));
        });
        let content = items.iter().fold(Content::new(), |content, item| match &item.data {
            Some(data) => content.data(item.mime.clone(), data.clone()),
            None => content.advertise(item.mime.clone()),
        });
        self.clipboard.set_selection(content).map_err(|e| e.to_string())
    }

    fn clear(&mut self) {
        let _ = self.clipboard.clear_selection();
    }
}
