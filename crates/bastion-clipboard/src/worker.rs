//! The clipboard worker: a single thread that owns all clipboard state and serialises CLIPRDR
//! callbacks (forwarded by the backend), OS clipboard events and timers.
//!
//! Nothing here runs on the session's async thread; the backend only enqueues [`Command`]s.

use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Instant;

use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy};
use ironrdp_cliprdr::loop_detector::{ClipboardSource, LoopDetectionConfig, LoopDetector};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags, FileContentsFlags,
    FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataResponse,
};
use ironrdp_cliprdr_native::data_control::find_mime_match;
use tracing::{debug, info, warn};

use crate::convert::{
    self, LOCAL_IMAGE_TYPES, LOCAL_TEXT_TYPES, LocalKind, MIME_BASTION_REMOTE, MIME_GNOME_FILES, MIME_HTML,
    MIME_PASSWORD_HINT, MIME_PNG, MIME_TEXT_PLAIN, MIME_TEXT_UTF8, MIME_URI_LIST, MIME_UTF8_STRING,
};
use crate::files::download::{Download, DownloadDir, DownloadError, Step};
use crate::files::local::LocalFileList;
use crate::files::{self, Limits};
use crate::flow::{Budget, FlowControl};
use crate::os::{OfferItem, OsClipboard, Transfer};
use crate::uri;

/// Format ID we use for "HTML Format" in our own format lists (registered-format range).
pub(crate) const HTML_FORMAT_ID: ClipboardFormatId = ClipboardFormatId(0xC0A0);
/// Unanswered format data requests we tolerate before failing new pastes immediately.
const MAX_IN_FLIGHT: usize = 8;
/// Local pastes waiting on one request.
const MAX_WAITERS: usize = 16;
/// Completed download directories kept on disk (current + previous remote copy).
const KEEP_DOWNLOADS: usize = 2;
/// A local selection change this soon after we delivered remote data is checked for an echo.
const ECHO_WINDOW: Duration = Duration::from_secs(3);
/// Max bytes served per FileContents range request.
const MAX_SERVE_CHUNK: u32 = 8 * 1024 * 1024;
/// Server data requests held back while the response budget is used up; more are refused.
const MAX_DEFERRED: usize = 16;

/// Work items for the worker thread.
pub(crate) enum Command {
    // --- from the CLIPRDR backend (session thread) ---
    /// A new channel/backend was created (connect or reconnect).
    Reset,
    Capabilities(ClipboardGeneralCapabilityFlags),
    RequestFormatList,
    Ready,
    FormatListResponse(bool),
    RemoteCopy(Vec<ClipboardFormat>),
    FormatDataRequest(ClipboardFormatId),
    /// A format data request beyond the request queue limit: answer with a failure.
    RefuseFormatData,
    /// `None` = failure response (or over the size limit).
    FormatDataResponse(Option<Vec<u8>>),
    RemoteFileList {
        files: Vec<FileDescriptor>,
        clip_data_id: Option<u32>,
    },
    FileContentsRequest(FileContentsRequest),
    /// A file contents request (by stream ID) beyond the request queue limit.
    RefuseFileContents(u32),
    FileContentsResponse {
        stream_id: u32,
        data: Option<Vec<u8>>,
    },
    Lock(u32),
    Unlock(u32),
    // --- from the OS clipboard ---
    /// Another client changed the local selection.
    LocalChanged,
    /// A local application pastes a type we advertised for the remote clipboard.
    Paste(Transfer),
    Shutdown,
}

impl core::fmt::Debug for Command {
    // Never print payloads: clipboard contents must not reach logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Reset => "Reset",
            Self::Capabilities(_) => "Capabilities",
            Self::RequestFormatList => "RequestFormatList",
            Self::Ready => "Ready",
            Self::FormatListResponse(_) => "FormatListResponse",
            Self::RemoteCopy(_) => "RemoteCopy",
            Self::FormatDataRequest(_) => "FormatDataRequest",
            Self::RefuseFormatData => "RefuseFormatData",
            Self::RefuseFileContents(_) => "RefuseFileContents",
            Self::FormatDataResponse(_) => "FormatDataResponse",
            Self::RemoteFileList { .. } => "RemoteFileList",
            Self::FileContentsRequest(_) => "FileContentsRequest",
            Self::FileContentsResponse { .. } => "FileContentsResponse",
            Self::Lock(_) => "Lock",
            Self::Unlock(_) => "Unlock",
            Self::LocalChanged => "LocalChanged",
            Self::Paste(_) => "Paste",
            Self::Shutdown => "Shutdown",
        };
        f.write_str(name)
    }
}

/// Worker configuration.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) files: bool,
    pub(crate) max_transfer_bytes: usize,
    /// Where download directories go; `None` = [`files::download_base`].
    pub(crate) download_base: Option<PathBuf>,
    /// How long a local paste waits for the remote before it is failed.
    pub(crate) paste_timeout: Duration,
    /// A file download with no progress for this long is abandoned.
    pub(crate) download_stall_timeout: Duration,
    /// Request/response accounting shared with the backend and the session.
    pub(crate) flow: FlowControl,
}

impl Config {
    pub(crate) fn new(files: bool, max_transfer_bytes: usize) -> Self {
        Self {
            files,
            max_transfer_bytes,
            download_base: None,
            paste_timeout: Duration::from_secs(10),
            download_stall_timeout: Duration::from_secs(90),
            flow: FlowControl::default(),
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            max_total_bytes: u64::try_from(self.max_transfer_bytes).unwrap_or(u64::MAX),
            max_files: files::DEFAULT_MAX_FILES,
        }
    }
}

/// An error surfaced to the session through [`ClipboardMessage::Error`] (logged, no contents).
#[derive(Debug)]
pub(crate) struct ClipError(pub(crate) String);

impl core::fmt::Display for ClipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for ClipError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// No channel, or waiting for the server's Monitor Ready.
    Down,
    /// Initial format list sent, waiting for the server's Format List Response.
    Initializing,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetch {
    Text(ClipboardFormatId),
    Html(ClipboardFormatId),
    Image(ClipboardFormatId),
    FileList,
}

impl Fetch {
    fn kind(self) -> Option<LocalKind> {
        match self {
            Self::Text(_) => Some(LocalKind::Text),
            Self::Html(_) => Some(LocalKind::Html),
            Self::Image(_) => Some(LocalKind::Png),
            Self::FileList => None,
        }
    }
}

/// A FormatDataRequest we sent. Kept until its response arrives, even after the local paste
/// gave up, because responses carry no ID and must be paired in order.
struct InFlight {
    fetch: Fetch,
    generation: u64,
    deadline: Instant,
    waiters: Vec<Transfer>,
}

/// Formats the remote currently offers, as we would request them.
#[derive(Debug, Default, Clone, Copy)]
struct RemoteFormats {
    text: Option<ClipboardFormatId>,
    html: Option<ClipboardFormatId>,
    image: Option<ClipboardFormatId>,
    file_list: Option<ClipboardFormatId>,
}

impl RemoteFormats {
    fn parse(formats: &[ClipboardFormat], files: bool) -> Self {
        let has = |id| formats.iter().any(|f| f.id() == id);
        let named = |name: &ClipboardFormatName| {
            formats.iter().find(|f| f.name.as_ref().is_some_and(|n| n.value() == name.value())).map(|f| f.id())
        };
        let text = [ClipboardFormatId::CF_UNICODETEXT, ClipboardFormatId::CF_TEXT, ClipboardFormatId::CF_OEMTEXT]
            .into_iter()
            .find(|&id| has(id));
        let image = [ClipboardFormatId::CF_DIBV5, ClipboardFormatId::CF_DIB].into_iter().find(|&id| has(id));
        Self {
            text,
            html: named(&ClipboardFormatName::HTML),
            image,
            file_list: if files { named(&ClipboardFormatName::FILE_LIST) } else { None },
        }
    }

    /// What to put on the local clipboard for this remote offer. A non-empty offer always
    /// carries [`MIME_BASTION_REMOTE`], which tells other sessions not to forward it.
    fn local_offer(&self) -> Vec<OfferItem> {
        let mut items = Vec::new();
        if self.file_list.is_some() {
            items.push(OfferItem::delayed(MIME_URI_LIST));
            items.push(OfferItem::delayed(MIME_GNOME_FILES));
        }
        if self.html.is_some() {
            items.push(OfferItem::delayed(MIME_HTML));
        }
        if self.text.is_some() {
            for m in [MIME_TEXT_UTF8, MIME_TEXT_PLAIN, MIME_UTF8_STRING] {
                items.push(OfferItem::delayed(m));
            }
        }
        if self.image.is_some() {
            items.push(OfferItem::delayed(MIME_PNG));
        }
        if !items.is_empty() {
            items.push(OfferItem { mime: MIME_BASTION_REMOTE.to_owned(), data: Some(b"1".to_vec()) });
        }
        items
    }

    fn fetch_for(&self, kind: LocalKind) -> Option<Fetch> {
        match kind {
            LocalKind::Text => self.text.map(Fetch::Text),
            LocalKind::Html => self.html.map(Fetch::Html),
            LocalKind::Png => self.image.map(Fetch::Image),
            LocalKind::UriList | LocalKind::GnomeFiles => self.file_list.map(|_| Fetch::FileList),
        }
    }
}

enum FileJob {
    Idle,
    /// File list requested.
    Listing {
        since: Instant,
    },
    Downloading {
        download: Download,
        stream_id: u32,
    },
    Done {
        paths: Vec<PathBuf>,
        dir: DownloadDir,
    },
    /// Failed for good (limits); a retry would fail the same way.
    Failed,
}

/// A server request that is answered with clipboard or file data.
#[derive(Debug)]
enum DataRequest {
    Format(ClipboardFormatId),
    File(FileContentsRequest),
}

pub(crate) struct Worker<O, P> {
    os: O,
    proxy: P,
    config: Config,
    channel: Channel,
    caps: ClipboardGeneralCapabilityFlags,
    /// A local change happened while the channel was not ready to announce it.
    local_dirty: bool,
    /// Bumped whenever the remote offer on the local clipboard changes or goes away.
    generation: u64,
    /// Set while the local clipboard holds our offer of the remote clipboard.
    remote: Option<RemoteFormats>,
    cache: HashMap<LocalKind, Vec<u8>>,
    in_flight: VecDeque<InFlight>,
    file_job: FileJob,
    file_waiters: Vec<Transfer>,
    kept_downloads: VecDeque<DownloadDir>,
    download_base: Option<PathBuf>,
    next_stream_id: u32,
    local_files: Option<Arc<LocalFileList>>,
    locked: HashMap<u32, Arc<LocalFileList>>,
    loops: LoopDetector,
    last_remote_delivery: Option<Instant>,
    epoch: Instant,
    /// Response bytes handed to the session and not yet written.
    budget: Budget,
    /// Data requests waiting for room in `budget`, oldest first.
    deferred: VecDeque<DataRequest>,
}

impl<O: OsClipboard, P: ClipboardMessageProxy> Worker<O, P> {
    pub(crate) fn new(os: O, proxy: P, config: Config) -> Self {
        let loops = LoopDetector::with_config(LoopDetectionConfig {
            window_ms: u64::try_from(ECHO_WINDOW.as_millis()).unwrap_or(3000),
            ..LoopDetectionConfig::default()
        });
        if let Some(base) = &config.download_base {
            files::register_base(base);
        }
        Self {
            os,
            proxy,
            budget: Budget::new(config.flow.shared()),
            deferred: VecDeque::new(),
            download_base: config.download_base.clone(),
            config,
            channel: Channel::Down,
            caps: ClipboardGeneralCapabilityFlags::empty(),
            local_dirty: false,
            generation: 0,
            remote: None,
            cache: HashMap::new(),
            in_flight: VecDeque::new(),
            file_job: FileJob::Idle,
            file_waiters: Vec::new(),
            kept_downloads: VecDeque::new(),
            next_stream_id: 1,
            local_files: None,
            locked: HashMap::new(),
            loops,
            last_remote_delivery: None,
            epoch: Instant::now(),
        }
    }

    pub(crate) fn run(mut self, receiver: &Receiver<Command>) {
        loop {
            // Requests waiting for the session to write earlier responses are retried quickly.
            let wait = if self.deferred.is_empty() { Duration::from_millis(100) } else { Budget::POLL };
            match receiver.recv_timeout(wait) {
                Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(command) => self.handle(command),
                Err(RecvTimeoutError::Timeout) => {}
            }
            self.tick(Instant::now());
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.remote.is_some() {
            self.os.clear();
        }
        self.reset_file_job();
        self.kept_downloads.clear();
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn send(&self, message: ClipboardMessage) {
        self.budget.charge(FlowControl::cost(&message));
        self.proxy.send_clipboard_message(message);
    }

    fn report(&self, message: String) {
        warn!("{message}");
        self.send(ClipboardMessage::Error(Box::new(ClipError(message))));
    }

    fn files_negotiated(&self) -> bool {
        self.config.files && self.caps.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED)
    }

    pub(crate) fn handle(&mut self, command: Command) {
        debug!(?command, "Clipboard command");
        match command {
            Command::Reset => self.reset(),
            Command::Capabilities(caps) => {
                debug!(?caps, "CLIPRDR capabilities negotiated");
                self.caps = caps;
            }
            Command::RequestFormatList => self.initial_format_list(),
            Command::Ready => {
                self.channel = Channel::Ready;
                if core::mem::take(&mut self.local_dirty) && self.remote.is_none() {
                    self.advertise_local();
                }
            }
            Command::FormatListResponse(ok) => {
                if !ok {
                    debug!("Remote rejected our format list");
                }
            }
            Command::RemoteCopy(formats) => self.remote_copy(&formats),
            Command::FormatDataRequest(format) => {
                self.budget.request_handled();
                self.data_request(DataRequest::Format(format));
            }
            Command::RefuseFormatData => {
                self.budget.request_handled();
                self.send(ClipboardMessage::SendFormatData(FormatDataResponse::new_error()));
            }
            Command::FormatDataResponse(data) => self.format_data_response(data),
            Command::RemoteFileList { files, clip_data_id } => self.remote_file_list(&files, clip_data_id),
            Command::FileContentsRequest(request) => {
                self.budget.request_handled();
                self.data_request(DataRequest::File(request));
            }
            Command::RefuseFileContents(stream_id) => {
                self.budget.request_handled();
                self.send(ClipboardMessage::SendFileContentsResponse(FileContentsResponse::new_error(stream_id)));
            }
            Command::FileContentsResponse { stream_id, data } => self.file_contents_response(stream_id, data),
            Command::Lock(id) => {
                if let Some(list) = &self.local_files
                    && self.locked.len() < ironrdp_cliprdr::MAX_LOCKED_FILE_LISTS
                {
                    self.locked.insert(id, Arc::clone(list));
                }
            }
            Command::Unlock(id) => {
                self.locked.remove(&id);
            }
            Command::LocalChanged => self.local_changed(),
            Command::Paste(transfer) => self.paste(transfer),
            Command::Shutdown => self.shutdown(),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------------------------

    fn reset(&mut self) {
        self.invalidate();
        // A new channel answers nothing sent on the old one.
        self.in_flight.clear();
        self.deferred.clear();
        self.budget.reset(Instant::now());
        self.channel = Channel::Down;
        self.caps = ClipboardGeneralCapabilityFlags::empty();
        if self.remote.take().is_some() {
            self.os.clear();
        }
        self.local_files = None;
        self.locked.clear();
        self.loops.clear();
        self.local_dirty = false;
    }

    /// Drops everything tied to the current remote offer.
    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.cache.clear();
        for request in &mut self.in_flight {
            request.waiters.clear();
        }
        self.reset_file_job();
    }

    fn reset_file_job(&mut self) {
        self.file_waiters.clear();
        match core::mem::replace(&mut self.file_job, FileJob::Idle) {
            FileJob::Done { dir, .. } => {
                self.kept_downloads.push_back(dir);
                while self.kept_downloads.len() > KEEP_DOWNLOADS {
                    self.kept_downloads.pop_front();
                }
            }
            FileJob::Downloading { download, .. } => drop(download),
            FileJob::Idle | FileJob::Listing { .. } | FileJob::Failed => {}
        }
    }

    pub(crate) fn tick(&mut self, now: Instant) {
        self.serve_deferred(now);
        for request in &mut self.in_flight {
            if request.deadline <= now && !request.waiters.is_empty() {
                debug!("Remote did not answer a paste in time");
                request.waiters.clear();
            }
        }
        let stalled = match &self.file_job {
            FileJob::Listing { since } => now.duration_since(*since) > self.config.download_stall_timeout,
            FileJob::Downloading { download, .. } => {
                now.duration_since(download.last_activity()) > self.config.download_stall_timeout
            }
            _ => false,
        };
        if stalled {
            self.report("Clipboard file download stalled; giving up".to_owned());
            self.file_waiters.clear();
            self.file_job = FileJob::Idle;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Local -> remote
    // -----------------------------------------------------------------------------------------

    fn initial_format_list(&mut self) {
        // Initialization-state FormatList must go through initiate_copy (it carries the
        // capabilities); a file list is announced once the channel is ready.
        let mimes = self.os.mime_types();
        let withheld = self.withheld(&mimes).is_some();
        let formats = if self.remote.is_some() || withheld { Vec::new() } else { self.local_formats(&mimes) };
        self.local_files = None;
        self.local_dirty = self.config.files && !withheld && self.local_file_paths(&mimes).is_some();
        self.channel = Channel::Initializing;
        self.send(ClipboardMessage::SendInitiateCopy(formats));
    }

    fn local_changed(&mut self) {
        if self.os.is_owner() {
            return;
        }
        if self.remote.is_some() {
            self.remote = None;
            self.invalidate();
        }
        if self.channel != Channel::Ready {
            self.local_dirty = true;
            return;
        }
        self.advertise_local();
    }

    /// Why the current local selection must not reach the remote, if it must not:
    ///
    /// * it is the remote clipboard of another Bastion session. Announcing it would hand one
    ///   server's data to another without the user pasting anything (and reading its file list
    ///   would make that session download the files);
    /// * a password manager marked it as a secret.
    ///
    /// Nothing but the (tiny) hint is read from the selection to decide this.
    fn withheld(&mut self, mimes: &[String]) -> Option<&'static str> {
        if self.os.is_owner() {
            return None;
        }
        if mimes.iter().any(|m| m == MIME_BASTION_REMOTE) {
            return Some("it is another session's remote clipboard");
        }
        if mimes.iter().any(|m| m == MIME_PASSWORD_HINT) {
            // Fail closed: a hint that cannot be read counts as "secret".
            let public = matches!(self.os.read(MIME_PASSWORD_HINT), Ok(Some(hint)) if hint.trim_ascii() != b"secret");
            if !public {
                return Some("a password manager marked it as secret");
            }
        }
        None
    }

    /// Whether the new local selection is just a clipboard manager re-publishing what we put
    /// there from the remote a moment ago.
    fn is_echo(&mut self, mimes: &[String]) -> bool {
        if !self.last_remote_delivery.is_some_and(|t| t.elapsed() < ECHO_WINDOW) {
            return false;
        }
        let candidate = LOCAL_TEXT_TYPES.iter().chain([&MIME_PNG]).find_map(|m| find_mime_match(m, mimes));
        let Some(mime) = candidate.map(str::to_owned) else { return false };
        match self.os.read(&mime) {
            Ok(Some(data)) => self.loops.would_cause_content_loop(&data, ClipboardSource::Local, self.now_ms()),
            _ => false,
        }
    }

    fn local_file_paths(&mut self, mimes: &[String]) -> Option<Vec<PathBuf>> {
        let gnome = if mimes.iter().any(|m| m == MIME_URI_LIST) {
            false
        } else if mimes.iter().any(|m| m == MIME_GNOME_FILES) {
            true
        } else {
            return None;
        };
        let data = self.os.read(if gnome { MIME_GNOME_FILES } else { MIME_URI_LIST }).ok().flatten()?;
        let paths = if gnome { uri::parse_gnome_copied_files(&data) } else { uri::parse_uri_list(&data) };
        (!paths.is_empty()).then_some(paths)
    }

    fn local_formats(&self, mimes: &[String]) -> Vec<ClipboardFormat> {
        let mut formats = Vec::new();
        if LOCAL_TEXT_TYPES.iter().any(|m| find_mime_match(m, mimes).is_some()) {
            formats.push(ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT));
        }
        if mimes.iter().any(|m| m == MIME_HTML) {
            formats.push(ClipboardFormat::new(HTML_FORMAT_ID).with_name(ClipboardFormatName::HTML));
        }
        if LOCAL_IMAGE_TYPES.iter().any(|m| mimes.iter().any(|x| x == m)) {
            formats.push(ClipboardFormat::new(ClipboardFormatId::CF_DIBV5));
            formats.push(ClipboardFormat::new(ClipboardFormatId::CF_DIB));
        }
        formats
    }

    fn advertise_local(&mut self) {
        let mimes = self.os.mime_types();
        if let Some(reason) = self.withheld(&mimes) {
            // An empty list also retracts whatever we announced before, so the remote cannot
            // go on requesting formats that would now be rendered from this selection.
            debug!(reason, "Not announcing the local clipboard to the remote");
            self.local_files = None;
            self.send(ClipboardMessage::SendInitiateCopy(Vec::new()));
            return;
        }
        if self.is_echo(&mimes) {
            debug!("Local clipboard change echoes remote data; not re-announcing it");
            return;
        }
        if self.files_negotiated()
            && let Some(paths) = self.local_file_paths(&mimes)
        {
            if self.is_our_download(&paths) {
                debug!("Local clipboard holds our own downloaded files; not re-announcing them");
                return;
            }
            match LocalFileList::build(&paths, &self.config.limits()) {
                Ok(list) => {
                    info!(entries = list.len(), "Offering local files to the remote clipboard");
                    let descriptors = list.descriptors().to_vec();
                    self.local_files = Some(Arc::new(list));
                    self.send(ClipboardMessage::SendInitiateFileCopy(descriptors));
                    return;
                }
                Err(e) => self.report(format!("Not offering copied files to the remote: {e}")),
            }
        }
        self.local_files = None;
        let formats = self.local_formats(&mimes);
        debug!(count = formats.len(), "Announcing local clipboard formats");
        self.send(ClipboardMessage::SendInitiateCopy(formats));
    }

    /// Whether `paths` are files downloaded from a remote clipboard, by this session or any
    /// other one (a session must not re-export what another session's remote sent).
    fn is_our_download(&self, paths: &[PathBuf]) -> bool {
        self.download_base.as_ref().is_some_and(|base| LocalFileList::top_level_within(paths, base))
            || files::are_downloads(paths)
    }

    // -----------------------------------------------------------------------------------------
    // Serving the remote's data requests
    // -----------------------------------------------------------------------------------------

    /// Whether answering `request` produces more than a few bytes.
    fn is_bulk(request: &DataRequest) -> bool {
        match request {
            DataRequest::Format(_) => true,
            DataRequest::File(request) => !request.flags.contains(FileContentsFlags::SIZE),
        }
    }

    /// Serves a data request now if earlier responses have been written out, holds it back
    /// (a few) or refuses it (the rest) otherwise. The server chooses how many requests it
    /// sends and each is answered with up to megabytes, so answering all of them at once would
    /// queue an unbounded amount of memory behind the socket.
    fn data_request(&mut self, request: DataRequest) {
        if !Self::is_bulk(&request) {
            self.serve(request);
            return;
        }
        let now = Instant::now();
        self.serve_deferred(now);
        if self.deferred.is_empty() && self.budget.has_room(now) {
            self.serve(request);
        } else if self.deferred.len() < MAX_DEFERRED {
            self.deferred.push_back(request);
        } else {
            self.refuse(&request);
        }
    }

    fn serve_deferred(&mut self, now: Instant) {
        while !self.deferred.is_empty() && self.budget.has_room(now) {
            if let Some(request) = self.deferred.pop_front() {
                self.serve(request);
            }
        }
    }

    fn serve(&mut self, request: DataRequest) {
        match request {
            DataRequest::Format(format) => self.render_local(format),
            DataRequest::File(request) => self.serve_file_contents(&request),
        }
    }

    fn refuse(&mut self, request: &DataRequest) {
        let message = match request {
            DataRequest::Format(_) => ClipboardMessage::SendFormatData(FormatDataResponse::new_error()),
            DataRequest::File(request) => {
                ClipboardMessage::SendFileContentsResponse(FileContentsResponse::new_error(request.stream_id))
            }
        };
        self.send(message);
    }

    fn read_first(&mut self, candidates: &[&str]) -> Result<(String, Vec<u8>), String> {
        let mimes = self.os.mime_types();
        for candidate in candidates {
            if let Some(m) = find_mime_match(candidate, &mimes).map(str::to_owned)
                && let Some(data) = self.os.read(&m)?
            {
                return Ok((m, data));
            }
        }
        Err("format no longer available locally".to_owned())
    }

    fn render_local(&mut self, format: ClipboardFormatId) {
        let max = self.config.max_transfer_bytes;
        let result = (|| -> Result<Vec<u8>, String> {
            if self.remote.is_some() {
                return Err("local clipboard holds the remote's data".to_owned());
            }
            // Checked again here: the selection may have changed since it was announced.
            let mimes = self.os.mime_types();
            if let Some(reason) = self.withheld(&mimes) {
                return Err(format!("local clipboard is withheld: {reason}"));
            }
            let out = match format {
                ClipboardFormatId::CF_UNICODETEXT => {
                    let (mime, data) = self.read_first(LOCAL_TEXT_TYPES)?;
                    convert::text_to_cf_unicodetext(&convert::local_text_to_string(&mime, &data))
                }
                f if f == HTML_FORMAT_ID => {
                    let (_, data) = self.read_first(&[MIME_HTML])?;
                    convert::local_html_to_cf_html(&data)
                }
                ClipboardFormatId::CF_DIB | ClipboardFormatId::CF_DIBV5 => {
                    let (mime, data) = self.read_first(LOCAL_IMAGE_TYPES)?;
                    let png = convert::local_image_to_png(&mime, &data, max).map_err(|e| e.to_string())?;
                    if format == ClipboardFormatId::CF_DIB {
                        convert::png_to_dib(&png)
                    } else {
                        convert::png_to_dibv5(&png)
                    }
                    .map_err(|e| e.to_string())?
                }
                _ => return Err("unsupported clipboard format".to_owned()),
            };
            if out.len() > max {
                return Err(format!("{} bytes exceeds the clipboard limit", out.len()));
            }
            Ok(out)
        })();
        let response = match result {
            Ok(data) => {
                debug!(format = format.value(), bytes = data.len(), "Sending local clipboard data");
                bastion_metrics::CLIPBOARD_BYTES.add(data.len() as u64);
                FormatDataResponse::new_data(data)
            }
            Err(error) => {
                debug!(format = format.value(), %error, "Could not render the local clipboard");
                FormatDataResponse::new_error()
            }
        };
        self.send(ClipboardMessage::SendFormatData(response));
    }

    fn serve_file_contents(&mut self, request: &FileContentsRequest) {
        let list = request.data_id.and_then(|id| self.locked.get(&id)).or(self.local_files.as_ref());
        let index = usize::try_from(request.index).ok();
        let response = match (list, index) {
            (Some(list), Some(index)) if request.flags.contains(FileContentsFlags::SIZE) => match list.size(index) {
                Some(size) => FileContentsResponse::new_size_response(request.stream_id, size),
                None => FileContentsResponse::new_error(request.stream_id),
            },
            (Some(list), Some(index)) if request.flags.contains(FileContentsFlags::RANGE) => {
                match list.read_range(index, request.position, request.requested_size.min(MAX_SERVE_CHUNK)) {
                    Ok(data) => {
                        bastion_metrics::CLIPBOARD_BYTES.add(data.len() as u64);
                        FileContentsResponse::new_data_response(request.stream_id, data)
                    }
                    Err(error) => {
                        debug!(%error, index, "Could not read a copied file");
                        FileContentsResponse::new_error(request.stream_id)
                    }
                }
            }
            _ => FileContentsResponse::new_error(request.stream_id),
        };
        self.send(ClipboardMessage::SendFileContentsResponse(response));
    }

    // -----------------------------------------------------------------------------------------
    // Remote -> local
    // -----------------------------------------------------------------------------------------

    fn remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let parsed = RemoteFormats::parse(formats, self.files_negotiated());
        let items = parsed.local_offer();
        self.invalidate();
        if items.is_empty() && self.remote.is_none() {
            // Nothing we can render: keep the user's local clipboard.
            debug!("No supported format in the remote clipboard");
            return;
        }
        debug!(formats = formats.len(), offered = items.len(), "Offering the remote clipboard locally");
        self.remote = Some(parsed);
        if let Err(error) = self.os.offer(&items, self.generation) {
            warn!(%error, "Could not take the local clipboard");
            self.os.clear();
            self.remote = None;
            if self.channel == Channel::Ready {
                self.advertise_local();
            }
        }
    }

    fn paste(&mut self, transfer: Transfer) {
        let Some(remote) = self.remote.filter(|_| transfer.generation() == self.generation) else {
            return; // stale: dropping fails the paste
        };
        let Some(kind) = LocalKind::from_mime(transfer.mime_type()) else { return };
        let Some(fetch) = remote.fetch_for(kind) else { return };
        if kind.is_files() {
            self.paste_files(transfer, kind);
            return;
        }
        if let Some(data) = self.cache.get(&kind) {
            transfer.finish(Some(data.clone()));
            return;
        }
        let generation = self.generation;
        if let Some(request) =
            self.in_flight.iter_mut().find(|r| r.fetch == fetch && r.generation == generation && !r.waiters.is_empty())
        {
            if request.waiters.len() < MAX_WAITERS {
                request.waiters.push(transfer);
            }
            return;
        }
        let Some(format) = self.request_format(fetch) else { return };
        self.in_flight.push_back(InFlight {
            fetch,
            generation,
            deadline: Instant::now() + self.config.paste_timeout,
            waiters: vec![transfer],
        });
        self.send(ClipboardMessage::SendInitiatePaste(format));
    }

    /// The format ID to request for `fetch`, if a request can be sent right now.
    fn request_format(&self, fetch: Fetch) -> Option<ClipboardFormatId> {
        if self.channel != Channel::Ready {
            debug!("Clipboard channel not ready; failing a paste");
            return None;
        }
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            warn!("Too many unanswered clipboard requests; failing a paste");
            return None;
        }
        let remote = self.remote?;
        match fetch {
            Fetch::Text(id) | Fetch::Html(id) | Fetch::Image(id) => Some(id),
            Fetch::FileList => remote.file_list,
        }
    }

    fn render_files(kind: LocalKind, paths: &[PathBuf]) -> Vec<u8> {
        if kind == LocalKind::GnomeFiles { uri::build_gnome_copied_files(paths) } else { uri::build_uri_list(paths) }
    }

    fn paste_files(&mut self, transfer: Transfer, kind: LocalKind) {
        match &self.file_job {
            FileJob::Done { paths, .. } => transfer.finish(Some(Self::render_files(kind, paths))),
            FileJob::Failed => {}
            FileJob::Listing { .. } | FileJob::Downloading { .. } => {
                if self.file_waiters.len() < MAX_WAITERS {
                    self.file_waiters.push(transfer);
                }
            }
            FileJob::Idle => {
                let Some(format) = self.request_format(Fetch::FileList) else { return };
                self.in_flight.push_back(InFlight {
                    fetch: Fetch::FileList,
                    generation: self.generation,
                    deadline: Instant::now() + self.config.paste_timeout,
                    waiters: Vec::new(),
                });
                self.file_job = FileJob::Listing { since: Instant::now() };
                self.file_waiters.push(transfer);
                self.send(ClipboardMessage::SendInitiatePaste(format));
            }
        }
    }

    fn decode(fetch: Fetch, data: &[u8]) -> Result<Vec<u8>, String> {
        match fetch {
            Fetch::Text(ClipboardFormatId::CF_UNICODETEXT) => Ok(convert::cf_unicodetext_to_text(data).into_bytes()),
            Fetch::Text(_) => Ok(convert::cf_text_to_text(data).into_bytes()),
            Fetch::Html(_) => convert::cf_html_to_local_html(data).map_err(|e| e.to_string()),
            Fetch::Image(ClipboardFormatId::CF_DIBV5) => convert::dibv5_to_png(data).map_err(|e| e.to_string()),
            Fetch::Image(_) => convert::dib_to_png(data).map_err(|e| e.to_string()),
            Fetch::FileList => Err("unexpected file list".to_owned()),
        }
    }

    fn format_data_response(&mut self, data: Option<Vec<u8>>) {
        bastion_metrics::CLIPBOARD_BYTES.add(data.as_ref().map_or(0, |d| d.len() as u64));
        let Some(request) = self.in_flight.pop_front() else {
            debug!("Discarding an unsolicited clipboard response");
            return;
        };
        let current = request.generation == self.generation && self.remote.is_some();
        let Some(kind) = request.fetch.kind() else {
            // Only failures for the file list arrive here (successes come as RemoteFileList).
            if current && matches!(self.file_job, FileJob::Listing { .. }) {
                debug!("Remote refused to send its file list");
                self.file_waiters.clear();
                self.file_job = FileJob::Idle;
            }
            return;
        };
        if !current {
            return;
        }
        let decoded = data.and_then(|data| match Self::decode(request.fetch, &data) {
            Ok(decoded) => Some(decoded),
            Err(error) => {
                warn!(%error, "Could not decode the remote clipboard");
                None
            }
        });
        if let Some(bytes) = &decoded {
            debug!(bytes = bytes.len(), "Delivering remote clipboard data locally");
            self.loops.record_content(bytes, ClipboardSource::Remote, self.now_ms());
            self.last_remote_delivery = Some(Instant::now());
            self.cache.insert(kind, bytes.clone());
        }
        // The last waiter takes the buffer instead of another copy of it.
        let mut waiters = request.waiters;
        let last = waiters.pop();
        for waiter in waiters {
            waiter.finish(decoded.clone());
        }
        if let Some(waiter) = last {
            waiter.finish(decoded);
        }
    }

    fn remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        let request = self.in_flight.pop_front();
        if request.as_ref().is_some_and(|r| r.fetch != Fetch::FileList) {
            warn!("File list arrived for a different request; clipboard request order is out of sync");
        }
        let current = request.is_some_and(|r| r.generation == self.generation) && self.remote.is_some();
        if !current || !matches!(self.file_job, FileJob::Listing { .. }) {
            return;
        }
        info!(entries = files.len(), "Downloading files from the remote clipboard");
        let base = match self.download_base.clone() {
            Some(base) => base,
            None => match files::download_base() {
                Ok(base) => {
                    files::sweep_stale(&base);
                    files::register_base(&base);
                    self.download_base = Some(base.clone());
                    base
                }
                Err(e) => {
                    self.fail_download(&DownloadError::Io(e), false);
                    return;
                }
            },
        };
        match Download::start(files, clip_data_id, &base, self.config.limits()) {
            Ok(download) => {
                self.file_job = FileJob::Downloading { download, stream_id: 0 };
                self.pump_download();
            }
            Err(e) => self.fail_download(&e, true),
        }
    }

    fn fail_download(&mut self, error: &DownloadError, permanent: bool) {
        self.report(format!("Clipboard file download failed: {error}"));
        self.file_waiters.clear();
        let retryable = matches!(error, DownloadError::RemoteFailed | DownloadError::Io(_));
        self.file_job = if permanent && !retryable { FileJob::Failed } else { FileJob::Idle };
    }

    fn pump_download(&mut self) {
        let FileJob::Downloading { download, stream_id } = &mut self.file_job else { return };
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
        match download.next(id) {
            Ok(Step::Request(request)) => {
                *stream_id = id;
                self.send(ClipboardMessage::SendFileContentsRequest(request));
            }
            Ok(Step::Done(paths)) => {
                let written = download.bytes_written();
                let FileJob::Downloading { download, .. } = core::mem::replace(&mut self.file_job, FileJob::Idle)
                else {
                    return;
                };
                info!(bytes = written, items = paths.len(), "Clipboard file download complete");
                let uri_list = uri::build_uri_list(&paths);
                self.loops.record_content(&uri_list, ClipboardSource::Remote, self.now_ms());
                self.last_remote_delivery = Some(Instant::now());
                for waiter in core::mem::take(&mut self.file_waiters) {
                    let kind = LocalKind::from_mime(waiter.mime_type()).unwrap_or(LocalKind::UriList);
                    waiter.finish(Some(Self::render_files(kind, &paths)));
                }
                self.file_job = FileJob::Done { paths, dir: download.into_dir() };
            }
            Err(e) => self.fail_download(&e, true),
        }
    }

    fn file_contents_response(&mut self, stream: u32, data: Option<Vec<u8>>) {
        bastion_metrics::CLIPBOARD_BYTES.add(data.as_ref().map_or(0, |d| d.len() as u64));
        let FileJob::Downloading { download, stream_id } = &mut self.file_job else { return };
        if *stream_id != stream {
            return;
        }
        match download.on_response(stream, data.as_deref()) {
            Ok(true) => self.pump_download(),
            Ok(false) => {}
            Err(e) => self.fail_download(&e, true),
        }
    }
}
