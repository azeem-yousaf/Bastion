//! The `CliprdrBackend` handed to `ironrdp-cliprdr`. Every callback runs on the session's async
//! thread, so each one only copies its (bounded) arguments into a [`Command`] for the worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use ironrdp_cliprdr::backend::{CliprdrBackend, CliprdrBackendFactory};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse, FileDescriptor,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::impl_as_any;

use crate::files::download::CHUNK_BYTES;
use crate::flow::{Admission, Shared};
use crate::worker::Command;

pub(crate) struct BackendFactory {
    pub(crate) commands: Sender<Command>,
    pub(crate) files: bool,
    pub(crate) max_transfer_bytes: usize,
    /// Request/response accounting shared with the worker.
    pub(crate) flow: Arc<Shared>,
}

impl CliprdrBackendFactory for BackendFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        let _ = self.commands.send(Command::Reset);
        Box::new(BastionBackend {
            commands: self.commands.clone(),
            files: self.files,
            max_transfer_bytes: self.max_transfer_bytes,
            flow: Arc::clone(&self.flow),
            flood_reported: AtomicBool::new(false),
        })
    }
}

#[derive(Debug)]
pub(crate) struct BastionBackend {
    commands: Sender<Command>,
    files: bool,
    max_transfer_bytes: usize,
    flow: Arc<Shared>,
    /// Set once this connection's server exceeded the request queue (logged once, not per PDU).
    flood_reported: AtomicBool,
}

impl_as_any!(BastionBackend);

impl BastionBackend {
    fn send(&self, command: Command) {
        if self.commands.send(command).is_err() {
            tracing::warn!("Clipboard worker is gone; dropping a CLIPRDR event");
        }
    }

    /// Queues a server request for the worker, or only its refusal once too many are waiting.
    /// The server decides how many requests it sends, so the queue must not grow with them.
    fn request(&self, serve: Command, refuse: Command) {
        let admission = self.flow.admit();
        if admission != Admission::Serve && !self.flood_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!("The remote sends clipboard requests faster than they can be answered; refusing the excess");
        }
        match admission {
            Admission::Serve => self.send(serve),
            Admission::Refuse => self.send(refuse),
            Admission::Drop => {}
        }
    }
}

/// Capabilities we ask for when file transfer is enabled.
pub(crate) fn file_capabilities() -> ClipboardGeneralCapabilityFlags {
    ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
        | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
        | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
        | ClipboardGeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED
}

impl CliprdrBackend for BastionBackend {
    fn temporary_directory(&self) -> &str {
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        if self.files { file_capabilities() } else { ClipboardGeneralCapabilityFlags::empty() }
    }

    fn on_ready(&mut self) {
        self.send(Command::Ready);
    }

    fn on_request_format_list(&mut self) {
        self.send(Command::RequestFormatList);
    }

    fn on_format_list_response(&mut self, ok: bool) {
        self.send(Command::FormatListResponse(ok));
    }

    fn on_process_negotiated_capabilities(&mut self, capabilities: ClipboardGeneralCapabilityFlags) {
        self.send(Command::Capabilities(capabilities));
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        self.send(Command::RemoteCopy(available_formats.to_vec()));
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.request(Command::FormatDataRequest(request.format), Command::RefuseFormatData);
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let data = (!response.is_error() && response.data().len() <= self.max_transfer_bytes)
            .then(|| response.data().to_vec());
        self.send(Command::FormatDataResponse(data));
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        let refuse = Command::RefuseFileContents(request.stream_id);
        self.request(Command::FileContentsRequest(request), refuse);
    }

    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        // We never request more than CHUNK_BYTES; anything bigger is a protocol violation.
        let ok = !response.is_error() && response.data().len() <= CHUNK_BYTES as usize;
        let data = ok.then(|| response.data().to_vec());
        self.send(Command::FileContentsResponse { stream_id: response.stream_id(), data });
    }

    fn on_lock(&mut self, data_id: LockDataId) {
        self.send(Command::Lock(data_id.0));
    }

    fn on_unlock(&mut self, data_id: LockDataId) {
        self.send(Command::Unlock(data_id.0));
    }

    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        self.send(Command::RemoteFileList { files: files.to_vec(), clip_data_id });
    }

    fn now_ms(&self) -> u64 {
        ironrdp_cliprdr_native::native_now_ms()
    }
}
