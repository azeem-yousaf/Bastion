//! The session engine.
//!
//! Runs on its own OS thread with a small Tokio runtime. The UI talks to it only through
//! [`SessionHandle`]: commands in (input, resize, clipboard, decisions), events out (status,
//! pointer, prompts), plus the shared framebuffer.
//!
//! Lifecycle: connect → active session → (network drop → auto-reconnect with the server's
//! auto-reconnect cookie) → … → disconnected.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::profile::{ConnectionSpeed, Profile};
use bastion_core::secrets::Secret;
use bastion_core::trust::{EndpointKind, TrustStore};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackendFactory};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, Credentials, DesktopSize, ServerName,
};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::pointer::DecodedPointer;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_pdu::rdp::session_info::ServerAutoReconnect;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_svc::SvcMessage;
use ironrdp_tokio::{FramedWrite as _, single_sequence_step_read, split_tokio_framed};
use smallvec::SmallVec;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::frame::{Rect, SharedFrame};
use crate::keep_active::KeepActive;
use crate::layout::DesktopLayout;
use crate::tls::{CertificateRejection, PinningVerifier, RejectionSlot};

/// Called (from the session thread) whenever the UI should look at events / the framebuffer.
pub type Waker = Arc<dyn Fn() + Send + Sync>;

pub struct ConnectParams {
    pub profile: Profile,
    pub password: Secret,
    /// `None` = reuse the host credentials for the gateway.
    pub gateway_password: Option<Secret>,
    pub layout: DesktopLayout,
    pub trust: Arc<Mutex<TrustStore>>,
    pub keyboard_layout: u32,
    pub client_name: String,
    /// Audio device host; `None` = PulseAudio/PipeWire. Tests inject an in-memory host.
    pub audio_host: Option<Arc<dyn bastion_audio::AudioHost>>,
    /// Camera host; `None` = V4L2. Tests inject an in-memory host.
    pub camera_host: Option<Arc<dyn bastion_camera::CameraHost>>,
}

#[derive(Debug)]
pub enum Command {
    Input(SmallVec<[FastPathInputEvent; 2]>),
    Layout(DesktopLayout),
    /// A CLIPRDR message from the clipboard worker, with the guard that releases its share of
    /// the clipboard's response budget once it was written (or dropped).
    Clipboard(ClipboardMessage, Option<bastion_clipboard::SentGuard>),
    /// Answer to [`Event::CertificatePrompt`].
    CertificateDecision {
        accept: bool,
    },
    RefreshScreen,
    Disconnect,
    /// Internal: replies from the graphics thread, to send on its channel.
    #[doc(hidden)]
    GfxReply(crate::gfx::GfxReply),
    /// Internal: the graphics pipeline cannot go on; ends the session with this message.
    #[doc(hidden)]
    GfxFailed(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    ConnectingGateway,
    Connecting,
    Authenticating,
    /// The computer didn't answer; Wake-on-LAN packets are being sent while it starts.
    Waking,
    Connected {
        width: u16,
        height: u16,
    },
    Reconnecting {
        attempt: u32,
        max: u32,
    },
}

#[derive(Debug, Clone)]
pub enum PointerEvent {
    Default,
    Hidden,
    Position { x: u16, y: u16 },
    Bitmap(Arc<DecodedPointer>),
}

#[derive(Debug, Clone)]
pub enum Event {
    Status(Status),
    Pointer(PointerEvent),
    CertificatePrompt(Box<CertificateRejection>),
    /// Non-fatal problem worth showing (e.g. "microphone unavailable").
    Notice(String),
    /// The session is over. `error` = abnormal termination.
    Disconnected {
        reason: String,
        error: bool,
    },
}

/// Input events as sent by the UI.
type InputEvents = SmallVec<[FastPathInputEvent; 2]>;

pub struct SessionHandle {
    cmd: mpsc::UnboundedSender<Command>,
    /// Input bypasses the command queue: a dedicated task writes it to the socket so it never
    /// waits behind graphics decoding (see `input_task`).
    input: mpsc::UnboundedSender<InputEvents>,
    events: std::sync::mpsc::Receiver<Event>,
    pub frame: Arc<SharedFrame>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// When the oldest input not yet picked up by the network thread was queued.
    input_queued: Arc<bastion_metrics::Stamp>,
    /// Connection quality measurements (for the UI's indicator).
    pub link: Arc<crate::link::LinkStats>,
    /// Set on disconnect so the engine gives up even while it is stuck in a socket write or a
    /// re-activation the remote computer never finishes (those cannot look at the command queue).
    cancel: watch::Sender<bool>,
}

impl SessionHandle {
    pub fn spawn(params: ConnectParams, waker: Waker) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = std::sync::mpsc::channel();
        let frame = Arc::new(SharedFrame::default());
        let input_queued = Arc::new(bastion_metrics::Stamp::default());
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let link = Arc::new(crate::link::LinkStats::default());
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let ctx = EngineCtx {
            cancel: cancel_rx,
            link: link.clone(),
            params,
            cmd_tx: cmd_tx.clone(),
            events: ev_tx,
            waker,
            frame: frame.clone(),
            input_queued: input_queued.clone(),
            gfx_active: Arc::default(),
            input_tx: input_tx.clone(),
            input_rx: Arc::new(tokio::sync::Mutex::new(input_rx)),
        };
        let thread = std::thread::Builder::new()
            .name("bastion-session".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        ctx.emit(Event::Disconnected { reason: format!("Cannot start runtime: {e}"), error: true });
                        return;
                    }
                };
                rt.block_on(run(ctx, cmd_rx));
            })
            .expect("spawn session thread");
        Self {
            cmd: cmd_tx,
            input: input_tx,
            events: ev_rx,
            frame,
            thread: Some(thread),
            input_queued,
            link,
            cancel: cancel_tx,
        }
    }

    pub fn send(&self, cmd: Command) {
        match cmd {
            Command::Input(events) => {
                self.input_queued.mark();
                let _ = self.input.send(events);
            }
            Command::Disconnect => {
                let _ = self.cmd.send(Command::Disconnect);
                let _ = self.cancel.send(true);
            }
            other => {
                let _ = self.cmd.send(other);
            }
        }
    }

    pub fn try_event(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let _ = self.cmd.send(Command::Disconnect);
        let _ = self.cancel.send(true);
        if let Some(t) = self.thread.take() {
            // Give the graceful shutdown a moment; never block the UI for long.
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !t.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

struct EngineCtx {
    params: ConnectParams,
    cmd_tx: mpsc::UnboundedSender<Command>,
    events: std::sync::mpsc::Sender<Event>,
    waker: Waker,
    frame: Arc<SharedFrame>,
    input_queued: Arc<bastion_metrics::Stamp>,
    /// Set once the graphics pipeline owns the shared frame (see `gfx::GfxShared::active`).
    gfx_active: Arc<AtomicBool>,
    link: Arc<crate::link::LinkStats>,
    /// Becomes true (or its sender goes away) once the user disconnected; see [`bounded`].
    cancel: watch::Receiver<bool>,
    input_tx: mpsc::UnboundedSender<InputEvents>,
    /// Owned by the running session's input task (locked for its lifetime).
    input_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<InputEvents>>>,
}

impl EngineCtx {
    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
        (self.waker)();
    }
}

#[derive(Debug)]
struct ClipboardProxy {
    tx: mpsc::UnboundedSender<Command>,
    /// Set once the clipboard exists (it is created with this proxy).
    flow: Arc<std::sync::OnceLock<bastion_clipboard::FlowControl>>,
}

impl ClipboardMessageProxy for ClipboardProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        // Taken here, on the worker thread right after it charged the message, so the guard
        // belongs to the connection the message was produced for: after a reconnect, queued
        // messages from the old connection release nothing of the new one's budget.
        let sent = self.flow.get().map(|f| f.track(&message));
        let _ = self.tx.send(Command::Clipboard(message, sent));
    }
}

enum ConnectFailure {
    Certificate(Box<CertificateRejection>),
    Error { message: String, retryable: bool },
    Cancelled,
}

enum SessionEnd {
    Graceful(GracefulDisconnectReason),
    UserClosed,
    ReconnectWithLayout(DesktopLayout),
    NetworkError(String),
    Fatal(String),
}

const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(10);

/// A session that stayed up this long counts as a working connection again. Anything shorter is
/// treated as one more failed reconnect attempt, so a server (or middlebox) that accepts the
/// sign-in and then drops the connection cannot keep Bastion re-authenticating forever.
const STABLE_SESSION: Duration = Duration::from_secs(30);

/// The reconnect attempt number after a session that lasted `lasted` was lost. `previous` is the
/// attempt that produced that session (0 for the first connection).
fn attempt_after_drop(previous: u32, lasted: Duration) -> u32 {
    if lasted >= STABLE_SESSION { 1 } else { previous.saturating_add(1) }
}

/// The remote computer chooses the final desktop size; it is checked before anything is
/// allocated for it (a 65535 x 65535 desktop would need 17 GB). Multi-monitor desktops are the
/// bounding box of all monitors, so the limit is RDP's virtual-desktop side plus an area cap
/// (see [`crate::frame::desktop_size_ok`]), not one monitor's 8192.
fn check_desktop_size(width: u16, height: u16) -> Result<(), String> {
    if !crate::frame::desktop_size_ok(u32::from(width), u32::from(height)) {
        warn!(width, height, "Remote computer reported an unsupported desktop size");
        return Err("The remote computer reported an unsupported desktop size.".to_owned());
    }
    Ok(())
}

/// Shown when the remote computer (or someone in between) picks a security protocol without
/// Network Level Authentication.
const NLA_REQUIRED: &str = "The remote computer did not agree to Network Level Authentication (NLA). \
                            Bastion never sends your password without it, so the connection was stopped.";

/// Whether the X.224 negotiation ended with CredSSP (NLA) selected.
///
/// The connector advertises TLS as well as CredSSP (as Windows clients do), and the server's
/// answer arrives in clear text before TLS. Without this check a server — or anyone on the
/// path — could select TLS-only, and the connector would then put the password in the Client
/// Info PDU for a server that never proved it knows the account.
fn nla_selected(state: &ClientConnectorState) -> bool {
    use ironrdp_pdu::nego::SecurityProtocol as P;
    matches!(
        state,
        ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol }
            if selected_protocol.intersects(P::HYBRID | P::HYBRID_EX)
    )
}

/// How long a socket write may go without progress before the connection is considered dead
/// (the remote computer stopped reading). A large write (a clipboard response can be hundreds
/// of megabytes) may take longer in total, as long as every [`WRITE_PIECE`] gets through.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Writes are made in pieces of this size, each with its own [`WRITE_TIMEOUT`].
const WRITE_PIECE: usize = 64 * 1024;

/// The session's socket writer, shared by the session loop and the input task (each write
/// holds the lock for the whole frame, so frames never interleave).
struct SocketWriter<W> {
    framed: W,
    /// A write started and did not finish (it failed, stalled or was cancelled): the stream
    /// ends part-way through a frame and nothing more may be written to it.
    torn: bool,
}

impl<W> SocketWriter<W> {
    fn new(framed: W) -> Self {
        Self { framed, torn: false }
    }
}

#[derive(Debug)]
enum WriteFailure {
    Io(std::io::Error),
    /// No progress for [`WRITE_TIMEOUT`].
    Stalled,
    /// An earlier write was left unfinished.
    Torn,
}

/// Writes one whole frame, giving up only when a piece makes no progress for `stall`.
///
/// Dropping the future part-way (on disconnect) marks the writer torn, so the stream is never
/// written to again after a half-written frame.
async fn write_frame_to(
    writer: &tokio::sync::Mutex<SocketWriter<Writer>>,
    bytes: &[u8],
    stall: Duration,
) -> Result<(), WriteFailure> {
    let mut w = writer.lock().await;
    if w.torn {
        return Err(WriteFailure::Torn);
    }
    // Cleared only once the whole frame is out.
    w.torn = true;
    for piece in bytes.chunks(WRITE_PIECE) {
        match tokio::time::timeout(stall, w.framed.write_all(piece)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(WriteFailure::Io(e)),
            Err(_) => return Err(WriteFailure::Stalled),
        }
    }
    w.torn = false;
    Ok(())
}
/// The goodbye sent on disconnect is best effort; it must not delay closing.
const SHUTDOWN_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
enum Interrupted {
    /// The user disconnected (or the session handle is gone).
    Cancelled,
    TimedOut,
}

/// Runs `fut`, giving up when the user disconnects or `limit` passes. A future that is ready
/// wins, so an ordinary write still goes out after Disconnect was requested.
async fn bounded<T>(
    cancel: &mut watch::Receiver<bool>,
    limit: Duration,
    fut: impl Future<Output = T>,
) -> Result<T, Interrupted> {
    tokio::select! {
        biased;
        v = fut => Ok(v),
        () = cancelled(cancel) => Err(Interrupted::Cancelled),
        () = tokio::time::sleep(limit) => Err(Interrupted::TimedOut),
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    // An error means the session handle was dropped, which is a disconnect as well.
    let _ = cancel.wait_for(|stop| *stop).await;
}

/// Lets a message through at most once per interval; used where a hostile server could
/// otherwise make Bastion log on every packet.
struct LogGate {
    last: Mutex<Option<std::time::Instant>>,
    suppressed: std::sync::atomic::AtomicU64,
}

impl LogGate {
    const INTERVAL: Duration = Duration::from_secs(10);

    const fn new() -> Self {
        Self { last: Mutex::new(None), suppressed: std::sync::atomic::AtomicU64::new(0) }
    }

    /// `Some(events since the last message, this one included)` when a message may be logged.
    fn pass(&self) -> Option<u64> {
        let seen = self.suppressed.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let now = std::time::Instant::now();
        if last.is_some_and(|t| now.duration_since(t) < Self::INTERVAL) {
            return None;
        }
        *last = Some(now);
        self.suppressed.fetch_sub(seen, Ordering::Relaxed);
        Some(seen)
    }
}

/// Zeroes a password copy that had to be a plain `String` for an IronRDP API.
fn wipe(s: &mut String) {
    drop(Secret::new(std::mem::take(s)));
}

/// The gateway connection target, whose password copy is wiped when it goes out of scope
/// (also when connecting is cancelled half-way). Deliberately not `Debug`.
struct GwTarget(ironrdp_mstsgu::GwConnectTarget);

impl Drop for GwTarget {
    fn drop(&mut self) {
        wipe(&mut self.0.gw_pass);
    }
}

async fn run(ctx: EngineCtx, mut cmd_rx: mpsc::UnboundedReceiver<Command>) {
    let p = &ctx.params.profile;
    info!(host = %p.host, port = p.port, gateway = p.gateway.as_ref().map(|g| g.host.as_str()), "Starting session");

    // Clipboard lives for the whole session so reconnects keep working.
    let clipboard = if p.clipboard.enabled {
        let opts = bastion_clipboard::ClipboardOptions {
            files: p.clipboard.files,
            max_transfer_bytes: p.clipboard.max_transfer_mb as usize * 1024 * 1024,
        };
        let flow = Arc::default();
        match bastion_clipboard::Clipboard::new(
            ClipboardProxy { tx: ctx.cmd_tx.clone(), flow: Arc::clone(&flow) },
            opts,
        ) {
            Ok(c) => {
                let _ = flow.set(c.flow_control());
                Some(c)
            }
            Err(e) => {
                warn!(error = %e, "Clipboard redirection disabled");
                ctx.emit(Event::Notice(format!("Clipboard sync unavailable: {e}")));
                None
            }
        }
    } else {
        None
    };
    let cliprdr_factory = clipboard.as_ref().map(|c| c.backend_factory());

    let mut layout = ctx.params.layout.normalized();
    let mut cookie: Option<ServerAutoReconnect> = None;
    let mut ever_connected = false;
    let mut attempt = 0u32;
    // Cleared when a UDP tunnel dies mid-session: reconnects then stay on TCP.
    let mut udp_ok = true;
    let max_attempts = if p.reconnect.enabled { p.reconnect.max_attempts } else { 0 };

    let (end_reason, is_error) = loop {
        if attempt > 0 {
            ctx.emit(Event::Status(Status::Reconnecting { attempt, max: max_attempts }));
            let delay = (Duration::from_secs(1) * 2u32.saturating_pow(attempt.saturating_sub(1).min(4)))
                .min(RECONNECT_BACKOFF_MAX);
            if wait_or_cancel(&mut cmd_rx, delay).await {
                break ("Disconnected.".to_owned(), false);
            }
        }

        let result = connect(&ctx, &layout, cliprdr_factory.as_deref(), cookie.clone(), udp_ok, &mut cmd_rx).await;
        if result.is_err() {
            // Nothing may keep a failed connection's socket open (e.g. during a certificate prompt).
            ctx.link.clear_connection();
        }
        let connected = match result {
            Ok(v) => v,
            Err(ConnectFailure::Cancelled) => break ("Disconnected.".to_owned(), false),
            Err(ConnectFailure::Certificate(rej)) => {
                ctx.emit(Event::CertificatePrompt(rej.clone()));
                match wait_decision(&mut cmd_rx).await {
                    Some(true) => {
                        if let Ok(mut t) = ctx.params.trust.lock()
                            && let Err(e) = t.pin(rej.kind, &rej.endpoint, &rej.der)
                        {
                            warn!(error = %e, "Could not persist certificate pin");
                        }
                        info!(endpoint = %rej.endpoint, "User trusted certificate; retrying");
                        continue;
                    }
                    _ => break ("Connection cancelled: the server's certificate was not trusted.".to_owned(), true),
                }
            }
            Err(ConnectFailure::Error { message, retryable }) => {
                if ever_connected && retryable && attempt < max_attempts {
                    attempt += 1;
                    warn!(%message, attempt, "Reconnect attempt failed");
                    continue;
                }
                break (message, true);
            }
        };

        ever_connected = true;
        let session_started = std::time::Instant::now();
        let end = active_session(&ctx, connected, &mut cmd_rx, &mut udp_ok, &mut cookie, &layout).await;
        // The latency probe holds a duplicate of the socket; drop it so the connection really
        // closes now, not when the UI lets go of the session.
        ctx.link.clear_connection();
        match end {
            SessionEnd::ReconnectWithLayout(new) => {
                info!("Reconnecting to apply new desktop size");
                layout = new;
                attempt = 0;
                cookie = cookie.take();
            }
            SessionEnd::UserClosed => break ("Disconnected.".to_owned(), false),
            SessionEnd::Graceful(reason) => {
                break (reason.description(), matches!(reason, GracefulDisconnectReason::Other(_)));
            }
            SessionEnd::Fatal(msg) => break (msg, true),
            SessionEnd::NetworkError(msg) => {
                if max_attempts == 0 {
                    break (format!("Connection lost: {msg}"), true);
                }
                // `attempt` is not reset by a successful connect: only a session that stayed up
                // starts the count again, so accept-then-drop cycles run out of attempts too.
                attempt = attempt_after_drop(attempt, session_started.elapsed());
                if attempt > max_attempts {
                    break (
                        format!(
                            "Connection lost: {msg}. It kept dropping right after reconnecting, so Bastion stopped trying."
                        ),
                        true,
                    );
                }
                warn!(%msg, attempt, "Connection lost; will auto-reconnect");
            }
        }
    };

    info!(reason = %end_reason, "Session ended");
    ctx.emit(Event::Disconnected { reason: end_reason, error: is_error });
}

/// Sleeps for `d`; returns true if the user disconnected meanwhile. Other commands are dropped.
async fn wait_or_cancel(rx: &mut mpsc::UnboundedReceiver<Command>, d: Duration) -> bool {
    let sleep = tokio::time::sleep(d);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return false,
            c = rx.recv() => match c {
                None | Some(Command::Disconnect) => return true,
                Some(_) => {}
            }
        }
    }
}

async fn wait_decision(rx: &mut mpsc::UnboundedReceiver<Command>) -> Option<bool> {
    loop {
        match rx.recv().await? {
            Command::CertificateDecision { accept } => return Some(accept),
            Command::Disconnect => return None,
            _ => {}
        }
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}
type Erased = Box<dyn AsyncReadWrite>;
type Framed = ironrdp_tokio::TokioFramed<Erased>;

/// Packets queued for the microphone uplink before new ones are dropped. Capture threads keep
/// producing when the session loop cannot write (slow link, or a server that stopped reading);
/// a packet is at most 192 kB, typically 10–20 ms of audio.
const MIC_UPLINK_CAPACITY: usize = 64;

type UplinkItem = (u32, Vec<SvcMessage>);

/// One microphone uplink message, marked when it is audio data (which may be dropped) rather
/// than a control PDU such as the FormatChange confirmation (which never is).
struct MicItem {
    item: UplinkItem,
    audio: bool,
}

/// Data produced on other threads for the session loop to send: microphone packets (bounded
/// here) and camera samples (bounded by the server's sample requests).
struct MicRx {
    mic: mpsc::UnboundedReceiver<MicItem>,
    /// Audio items currently in `mic`.
    queued_audio: Arc<AtomicUsize>,
    camera: mpsc::UnboundedReceiver<UplinkItem>,
}

impl MicRx {
    async fn recv(&mut self) -> Option<UplinkItem> {
        tokio::select! {
            Some(m) = self.mic.recv() => {
                if m.audio {
                    self.queued_audio.fetch_sub(1, Ordering::AcqRel);
                }
                Some(m.item)
            }
            Some(m) = self.camera.recv() => Some(m),
            else => None,
        }
    }
}

/// The microphone side of the uplink. One queue keeps control PDUs in order behind the audio
/// sent before them; only audio counts against [`MIC_UPLINK_CAPACITY`].
#[derive(Clone)]
struct MicTx {
    tx: mpsc::UnboundedSender<MicItem>,
    queued_audio: Arc<AtomicUsize>,
}

struct UplinkTx {
    mic: MicTx,
    camera: mpsc::UnboundedSender<UplinkItem>,
}

fn uplink() -> (UplinkTx, MicRx) {
    let (mic_tx, mic_rx) = mpsc::unbounded_channel();
    let queued_audio = Arc::new(AtomicUsize::new(0));
    let (cam_tx, cam_rx) = mpsc::unbounded_channel();
    (
        UplinkTx { mic: MicTx { tx: mic_tx, queued_audio: queued_audio.clone() }, camera: cam_tx },
        MicRx { mic: mic_rx, queued_audio, camera: cam_rx },
    )
}

/// Whether an AUDIO_INPUT uplink message is captured audio (Data Incoming followed by Data),
/// as opposed to a control PDU.
fn is_mic_audio(msgs: &[SvcMessage]) -> bool {
    use ironrdp_dvc::pdu::{DrdynvcDataPdu, DrdynvcServerPdu};
    let Some(Ok(first)) = msgs.first().map(SvcMessage::encode_unframed_pdu) else { return false };
    matches!(
        ironrdp_core::decode::<DrdynvcServerPdu>(&first),
        Ok(DrdynvcServerPdu::Data(DrdynvcDataPdu::Data(d)))
            if d.data().first() == Some(&ironrdp_rdpeai::pdu::MSG_SNDIN_DATA_INCOMING)
    )
}

static MIC_DROP_LOG: LogGate = LogGate::new();
static MIC_BUSY_LOG: LogGate = LogGate::new();

/// The microphone's way into the session loop: never blocks the capture thread and never
/// queues more than [`MIC_UPLINK_CAPACITY`] audio packets — the newest is dropped instead.
/// Control PDUs (the FormatChange confirmation) are always queued.
fn mic_uplink(tx: MicTx) -> ironrdp_rdpeai::client::DvcUplink {
    Box::new(move |id, msgs| {
        let audio = is_mic_audio(&msgs);
        if audio {
            let reserved = tx
                .queued_audio
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MIC_UPLINK_CAPACITY).then_some(n + 1));
            if reserved.is_err() {
                if tx.tx.is_closed() {
                    return Err(ironrdp_pdu::pdu_other_err!("microphone uplink closed"));
                }
                if let Some(dropped) = MIC_DROP_LOG.pass() {
                    warn!(dropped, "Microphone audio dropped: the connection is not keeping up");
                }
                return Ok(());
            }
        }
        if tx.tx.send(MicItem { item: (id, msgs), audio }).is_err() {
            return Err(ironrdp_pdu::pdu_other_err!("microphone uplink closed"));
        }
        Ok(())
    })
}

/// Lets only one AUDIO_INPUT channel of a session record at a time.
///
/// The server may open the channel any number of times, and every open one would otherwise
/// start its own capture thread and sound-server connection.
struct SingleCapture<H> {
    inner: H,
    /// Shared by all of the session's channel instances: true while one of them records.
    busy: Arc<AtomicBool>,
    holding: bool,
}

impl<H> SingleCapture<H> {
    fn new(inner: H, busy: Arc<AtomicBool>) -> Self {
        Self { inner, busy, holding: false }
    }

    fn release(&mut self) {
        if std::mem::take(&mut self.holding) {
            self.busy.store(false, Ordering::Release);
        }
    }
}

impl<H> Drop for SingleCapture<H> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<H: ironrdp_rdpeai::client::RdpeaiCaptureHandler> ironrdp_rdpeai::client::RdpeaiCaptureHandler
    for SingleCapture<H>
{
    fn supported_formats(&self) -> &[ironrdp_rdpeai::AudioFormat] {
        self.inner.supported_formats()
    }

    fn choose_formats(&self, server_formats: &[ironrdp_rdpeai::AudioFormat]) -> Vec<ironrdp_rdpeai::AudioFormat> {
        self.inner.choose_formats(server_formats)
    }

    fn open(
        &mut self,
        capture_format: &ironrdp_rdpeai::AudioFormat,
        encode_format: &ironrdp_rdpeai::AudioFormat,
        packet_size: usize,
        sink: ironrdp_rdpeai::client::AudioPacketSink,
    ) -> i32 {
        use ironrdp_rdpeai::pdu::OpenReplyPdu;
        if !self.holding {
            if self.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
                if let Some(refused) = MIC_BUSY_LOG.pass() {
                    warn!(refused, "Refused a second microphone stream for the same session");
                }
                return OpenReplyPdu::E_FAIL;
            }
            self.holding = true;
        }
        let result = self.inner.open(capture_format, encode_format, packet_size, sink);
        if result != OpenReplyPdu::S_OK {
            self.release();
        }
        result
    }

    fn set_format(&mut self, encode_format: &ironrdp_rdpeai::AudioFormat, packet_size: usize) -> bool {
        self.inner.set_format(encode_format, packet_size)
    }

    fn close(&mut self) {
        self.inner.close();
        self.release();
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Maps a connector error to (user-facing message, retryable). Technical detail goes to the log only.
pub(crate) fn friendly_connector_error(e: &ironrdp_connector::ConnectorError) -> (String, bool) {
    use ironrdp_connector::ConnectorErrorKind as K;
    use sspi::ErrorKind as S;
    let detail = format!("{e:#}");
    let lower = detail.to_ascii_lowercase();
    match e.kind() {
        K::Credssp(se) => match se.error_type {
            S::LogonDenied | S::InvalidToken | S::NoCredentials | S::UnknownCredentials | S::WrongCredentialHandle => (
                "Sign-in failed: the username or password is incorrect, or this account is not allowed to sign in remotely.".into(),
                false,
            ),
            S::TimeSkew => ("Sign-in failed: this computer's clock differs too much from the server's.".into(), false),
            S::NoAuthenticatingAuthority | S::NoTgtReply => {
                ("Sign-in failed: the domain controller could not be reached to verify your account.".into(), false)
            }
            S::CertificateUnknown | S::UntrustedRoot | S::CertificateExpired => {
                ("Sign-in failed: the server's identity could not be verified during authentication.".into(), false)
            }
            _ => ("Network Level Authentication failed. Check your username, password and domain.".into(), false),
        },
        K::AccessDenied => ("Access denied by the remote computer.".into(), false),
        K::Negotiation(n) => (negotiation_message(n), false),
        _ if lower.contains("connection reset") || lower.contains("broken pipe") || lower.contains("unexpected eof") => {
            ("The connection was interrupted while signing in.".into(), true)
        }
        _ if lower.contains("timed out") => ("Timed out while connecting.".into(), true),
        _ => ("Could not connect to the remote computer. See the log for details.".into(), true),
    }
}

fn negotiation_message(n: &ironrdp_connector::NegotiationFailure) -> String {
    let code = format!("{n:?}");
    if code.contains("HybridRequired") {
        "The remote computer requires Network Level Authentication, which failed to start.".into()
    } else if code.contains("SslRequired") || code.contains("SslNotAllowed") {
        "The remote computer's security layer settings are not compatible with Bastion (TLS required).".into()
    } else {
        format!("The remote computer refused the security negotiation ({code}).")
    }
}

async fn connect(
    ctx: &EngineCtx,
    layout: &DesktopLayout,
    cliprdr: Option<&(dyn CliprdrBackendFactory + Send)>,
    cookie: Option<ServerAutoReconnect>,
    udp: bool,
    cmd_rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<Connected, ConnectFailure> {
    let fut = connect_inner(ctx, layout, cliprdr, cookie, udp);
    tokio::pin!(fut);
    // Waking a computer adds up to two minutes before the connection itself starts.
    let wake = if ctx.params.profile.wake.configured().is_some() { Duration::from_secs(130) } else { Duration::ZERO };
    let timeout = tokio::time::sleep(CONNECT_TIMEOUT * 3 + wake);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            r = &mut fut => return r,
            _ = &mut timeout => return Err(ConnectFailure::Error { message: "Timed out while connecting.".into(), retryable: true }),
            c = cmd_rx.recv() => match c {
                None | Some(Command::Disconnect) => return Err(ConnectFailure::Cancelled),
                Some(_) => {} // input before connection is meaningless
            }
        }
    }
}

async fn connect_inner(
    ctx: &EngineCtx,
    layout: &DesktopLayout,
    cliprdr: Option<&(dyn CliprdrBackendFactory + Send)>,
    cookie: Option<ServerAutoReconnect>,
    udp: bool,
) -> Result<Connected, ConnectFailure> {
    let p = &ctx.params.profile;
    let insecure = p.security.allow_insecure_tls;
    let rejected: RejectionSlot = Arc::default();
    let cert_failure = |rejected: &RejectionSlot, message: String| match rejected.lock().ok().and_then(|mut s| s.take())
    {
        Some(rej) => ConnectFailure::Certificate(Box::new(rej)),
        None => ConnectFailure::Error { message, retryable: true },
    };

    let started = std::time::Instant::now();
    let mut phases = Phases::default();
    // 1. Transport: RD Gateway tunnel or direct TCP.
    let (stream, client_addr, tcp_peer): (Erased, SocketAddr, Option<SocketAddr>) = if let Some(gw) = &p.gateway {
        ctx.emit(Event::Status(Status::ConnectingGateway));
        if p.wake.on_connect
            && let Some((mac, to)) = p.wake.configured()
        {
            // Only helps when this computer is on the remote computer's network; harmless otherwise.
            match bastion_core::wol::send(mac, to) {
                Ok(()) => debug!(%mac, "Sent Wake-on-LAN before connecting through the gateway"),
                Err(e) => debug!(error = %e, "Could not send Wake-on-LAN"),
            }
        }
        let endpoint = gw.endpoint();
        let verifier = Arc::new(PinningVerifier::new(
            ctx.params.trust.clone(),
            EndpointKind::Gateway,
            endpoint.clone(),
            insecure,
            rejected.clone(),
        ));
        let (gw_user, gw_pass) = if gw.same_credentials {
            (p.qualified_username(), ctx.params.password.expose().to_owned())
        } else {
            let user = if gw.domain.trim().is_empty() {
                gw.username.clone()
            } else {
                format!("{}\\{}", gw.domain.trim(), gw.username.trim())
            };
            (user, ctx.params.gateway_password.as_ref().map(|s| s.expose().to_owned()).unwrap_or_default())
        };
        // IronRDP wants the password as a plain `String` (and keeps its own copies for the
        // tunnel's lifetime); ours is wiped as soon as this function is done with it.
        let target = GwTarget(ironrdp_mstsgu::GwConnectTarget {
            gw_endpoint: endpoint.clone(),
            gw_user,
            gw_pass,
            smart_card: None,
            server: p.host.trim().to_owned(),
        });
        let (validation, callback) = if insecure {
            (ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate, None)
        } else {
            (ironrdp_tls::CertificateValidation::Strict, Some(verifier.gateway_callback()))
        };
        let gw = ironrdp_mstsgu::GwClient::connect_with_port_and_certificate_validation(
            &target.0,
            &ctx.params.client_name,
            p.port,
            validation,
            callback,
        );
        let connected = tokio::time::timeout(CONNECT_TIMEOUT, gw).await;
        drop(target);
        let (client, addr) = match connected {
            Err(_) => {
                return Err(ConnectFailure::Error {
                    message: format!("Timed out reaching gateway {endpoint}."),
                    retryable: true,
                });
            }
            Ok(Err(e)) => {
                let msg = gateway_error_message(&e, &endpoint);
                return Err(match rejected.lock().ok().and_then(|mut s| s.take()) {
                    Some(rej) => ConnectFailure::Certificate(Box::new(rej)),
                    None => ConnectFailure::Error { retryable: !msg.1, message: msg.0 },
                });
            }
            Ok(Ok(v)) => v,
        };
        info!(%endpoint, "RD Gateway tunnel established");
        let probe = crate::link::TcpProbe::find_by_local_addr(addr);
        if probe.is_none() {
            debug!("Gateway socket not found; latency comes from the remote computer's reports only");
        }
        ctx.link.set_connection(probe, true);
        (Box::new(client), addr, None)
    } else {
        ctx.emit(Event::Status(Status::Connecting));
        let target = (p.host.trim(), p.port);
        let wake = p.wake.on_connect.then(|| p.wake.configured()).flatten();
        let tcp = if let Some((mac, to)) = wake {
            use crate::wake::{WakeError, WakePlan, connect_waking};
            let woken = connect_waking(
                WakePlan::new(mac, to),
                || tokio::net::TcpStream::connect(target),
                || ctx.emit(Event::Status(Status::Waking)),
            )
            .await;
            match woken {
                Ok(s) => s,
                Err(WakeError::Refused(e)) => {
                    return Err(ConnectFailure::Error {
                        message: format!("Cannot reach {}:{}: {e}", p.host, p.port),
                        retryable: true,
                    });
                }
                Err(WakeError::NoAnswer { waited }) => {
                    return Err(ConnectFailure::Error {
                        message: format!(
                            "{} did not wake up within {} seconds. Check that Wake-on-LAN is enabled in its \
                             BIOS/UEFI and network adapter settings, and that you are on the same network.",
                            p.host.trim(),
                            waited.as_secs()
                        ),
                        retryable: true,
                    });
                }
            }
        } else {
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(target)).await {
                Err(_) => {
                    return Err(ConnectFailure::Error {
                        message: format!("Timed out connecting to {}:{}.", p.host, p.port),
                        retryable: true,
                    });
                }
                Ok(Err(e)) => {
                    return Err(ConnectFailure::Error {
                        message: format!("Cannot reach {}:{}: {e}", p.host, p.port),
                        retryable: true,
                    });
                }
                Ok(Ok(s)) => s,
            }
        };
        let _ = tcp.set_nodelay(true);
        ctx.link.set_connection(crate::link::TcpProbe::new(std::os::fd::AsFd::as_fd(&tcp)), false);
        let addr = tcp.local_addr().map_err(|e| ConnectFailure::Error { message: e.to_string(), retryable: true })?;
        let peer = tcp.peer_addr().ok();
        (Box::new(tcp), addr, peer)
    };
    // UDP is direct only: through an RD Gateway it needs the gateway's own UDP channel.
    let udp_peer = tcp_peer.filter(|_| udp && p.display.udp);

    phases.transport = started.elapsed();
    // 2. RDP negotiation, TLS (with our verifier), CredSSP/NLA, capability exchange.
    ctx.emit(Event::Status(Status::Connecting));
    let (uplink_tx, mic_rx) = uplink();
    let mut connector = build_connector(ctx, layout, client_addr, cliprdr, uplink_tx, udp_peer.is_some());
    if let Some(c) = cookie {
        connector = connector.with_auto_reconnect_cookie(c);
    }
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let err = |e: ironrdp_connector::ConnectorError| {
        let (message, retryable) = friendly_connector_error(&e);
        error!(error = %format!("{e:#}"), "Connection failed");
        ConnectFailure::Error { message, retryable }
    };
    let t = std::time::Instant::now();
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await.map_err(err)?;
    phases.negotiate = t.elapsed();
    // Before TLS and long before any credentials: NLA or nothing.
    let nla_required = || {
        error!("Security negotiation ended without Network Level Authentication; refusing to send credentials");
        ConnectFailure::Error { message: NLA_REQUIRED.into(), retryable: false }
    };
    if !nla_selected(&connector.state) {
        return Err(nla_required());
    }
    let (stream, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(ConnectFailure::Error {
            message: "Unexpected data before TLS handshake.".into(),
            retryable: false,
        });
    }
    let rdp_endpoint = format!("{}:{}", p.host.trim().to_ascii_lowercase(), p.port);
    let verifier = Arc::new(PinningVerifier::new(
        ctx.params.trust.clone(),
        EndpointKind::Rdp,
        rdp_endpoint,
        insecure,
        rejected.clone(),
    ));
    let t = std::time::Instant::now();
    let (tls, server_key) = crate::tls::upgrade(stream, p.host.trim(), verifier)
        .await
        .map_err(|e| cert_failure(&rejected, format!("TLS handshake with the remote computer failed: {e}")))?;
    phases.tls = t.elapsed();
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    if !connector.should_perform_credssp() {
        // Second line of defence: the connector itself must be about to run CredSSP.
        return Err(nla_required());
    }
    let mut framed: Framed = ironrdp_tokio::TokioFramed::new(Box::new(tls) as Erased);

    ctx.emit(Event::Status(Status::Authenticating));
    let t = std::time::Instant::now();
    let mut tunnel: Option<crate::udp::UdpTunnel> = None;
    let outcome = ironrdp_tokio::connect_finalize_with_multitransport(
        upgraded,
        connector,
        &mut framed,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        ServerName::new(p.host.trim()),
        server_key.clone(),
        None,
        async |request: ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu, _soft_sync: bool| {
            Ok(open_udp(&mut tunnel, udp_peer, p.host.trim(), &server_key, request).await)
        },
    )
    .await
    .map_err(err)?;
    let result = match outcome {
        ironrdp_connector::ConnectionOutcome::Connected(r) => r,
        ironrdp_connector::ConnectionOutcome::Redirected(_) => {
            return Err(ConnectFailure::Error {
                message:
                    "The server asked to redirect to another session host (RDS farm); redirection is not supported yet."
                        .into(),
                retryable: false,
            });
        }
    };
    phases.finalize = t.elapsed();
    info!(
        width = result.desktop_size.width,
        height = result.desktop_size.height,
        transport_ms = phases.transport.as_millis(),
        negotiate_ms = phases.negotiate.as_millis(),
        tls_ms = phases.tls.as_millis(),
        auth_and_setup_ms = phases.finalize.as_millis(),
        total_ms = started.elapsed().as_millis(),
        gateway = p.gateway.is_some(),
        udp = tunnel.is_some(),
        "RDP session established"
    );
    Ok((result, framed, Some(mic_rx), tunnel))
}

/// A connected session: the result, the TCP connection, the microphone uplink and the UDP
/// tunnel when Windows offered one and it came up.
type Connected = (ConnectionResult, Framed, Option<MicRx>, Option<crate::udp::UdpTunnel>);

/// Answers an Initiate Multitransport Request: opens the UDP tunnel for a reliable-UDP request
/// on a direct connection, and declines everything else (the session then stays on TCP).
async fn open_udp(
    slot: &mut Option<crate::udp::UdpTunnel>,
    peer: Option<SocketAddr>,
    host: &str,
    server_key: &[u8],
    request: ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu,
) -> ironrdp_connector::MultitransportResult {
    use ironrdp_pdu::rdp::multitransport::{MultitransportResponsePdu, RequestedProtocol};
    let decline = ironrdp_connector::MultitransportResult::Failure(MultitransportResponsePdu::E_ABORT);
    let Some(peer) = peer else { return decline };
    if slot.is_some() || request.requested_protocol != RequestedProtocol::UdpFecR {
        debug!(protocol = ?request.requested_protocol, "Declining additional multitransport request");
        return decline;
    }
    let params = crate::udp::TunnelParams {
        peer,
        server_name: host.to_owned(),
        server_key: server_key.to_vec(),
        request_id: request.request_id,
        cookie: request.security_cookie,
    };
    let started = std::time::Instant::now();
    match crate::udp::UdpTunnel::connect(params).await {
        Ok(t) => {
            info!(setup_ms = started.elapsed().as_millis(), version = t.version, "UDP transport ready");
            *slot = Some(t);
            ironrdp_connector::MultitransportResult::Success
        }
        Err(e) => {
            warn!(error = %e, setup_ms = started.elapsed().as_millis(), "UDP transport unavailable; staying on TCP");
            decline
        }
    }
}

/// How long each connection phase took (logged once per connection).
#[derive(Debug, Default)]
struct Phases {
    /// TCP connect, or the whole RD Gateway tunnel setup.
    transport: Duration,
    /// X.224 security negotiation.
    negotiate: Duration,
    tls: Duration,
    /// CredSSP/NLA sign-in, licensing and capability exchange.
    finalize: Duration,
}

fn gateway_error_message(e: &ironrdp_error::Error<ironrdp_mstsgu::GwErrorKind>, endpoint: &str) -> (String, bool) {
    use ironrdp_mstsgu::GwErrorKind as K;
    let detail = format!("{e:#}");
    error!(error = %detail, "Gateway connection failed");
    match e.kind() {
        K::HttpStatus(401) | K::HttpStatus(403) => (
            "The RD Gateway rejected your credentials (wrong username/password or not authorised to use this gateway)."
                .into(),
            true,
        ),
        K::HttpStatus(404) => (format!("{endpoint} does not look like an RD Gateway (HTTP 404)."), true),
        K::HttpStatus(code) => (format!("RD Gateway returned HTTP {code}."), false),
        K::GatewayCode(code) => (
            format!(
                "RD Gateway refused the connection to the remote computer ({}, {code:#010x}). Check the computer name and that you are allowed to reach it.",
                ironrdp_mstsgu::gateway_code_label(*code).unwrap_or("unknown")
            ),
            true,
        ),
        K::ConsentDeclined => ("The gateway's consent message was declined.".into(), true),
        K::Connect => (format!("Cannot reach the RD Gateway {endpoint}. Check the address and your network."), false),
        _ => ("The RD Gateway connection failed. See the log for details.".into(), false),
    }
}

/// What the client tells Windows at sign-in for a connection-speed choice: the network type
/// (Windows measures the link itself only for `Autodetect`) and the visual effects to draw.
fn experience(speed: ConnectionSpeed) -> (ironrdp_pdu::gcc::ConnectionType, PerformanceFlags) {
    use ironrdp_pdu::gcc::ConnectionType;
    let full = PerformanceFlags::ENABLE_FONT_SMOOTHING | PerformanceFlags::ENABLE_DESKTOP_COMPOSITION;
    match speed {
        ConnectionSpeed::Auto => (ConnectionType::Autodetect, full),
        ConnectionSpeed::Lan => (ConnectionType::Lan, full),
        ConnectionSpeed::Broadband => (ConnectionType::BroadbandHigh, full | PerformanceFlags::DISABLE_WALLPAPER),
        // Font smoothing stays on: it costs little and text is unreadable without it. Visual
        // styles stay on too (as mstsc does for slow links); Windows 10+ barely draws without them.
        ConnectionSpeed::Low => (
            ConnectionType::BroadbandLow,
            PerformanceFlags::ENABLE_FONT_SMOOTHING
                | PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_CURSOR_SHADOW,
        ),
    }
}

fn timezone() -> TimezoneInfo {
    // `time`'s local-offset API refuses to work in multi-threaded processes; ask libc directly.
    let offset_min = {
        let now: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() { 0 } else { (tm.tm_gmtoff / 60) as i32 }
    };
    TimezoneInfo { bias: -offset_min, ..TimezoneInfo::default() }
}

fn build_connector(
    ctx: &EngineCtx,
    layout: &DesktopLayout,
    client_addr: SocketAddr,
    cliprdr: Option<&(dyn CliprdrBackendFactory + Send)>,
    uplink: UplinkTx,
    udp: bool,
) -> ClientConnector {
    let p = &ctx.params.profile;
    let primary = layout.primary();
    let (_, _, bw, bh) = layout.bounds();
    let gcc = layout.gcc_monitors();

    // ── Dynamic channels ──
    let mut drdynvc = DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let display = p.display.clone();
    drdynvc = drdynvc.with_dynamic_channel_factory(ironrdp_egfx::CHANNEL_NAME, {
        let shared = crate::gfx::GfxShared {
            frame: ctx.frame.clone(),
            waker: ctx.waker.clone(),
            replies: ctx.cmd_tx.clone(),
            active: ctx.gfx_active.clone(),
        };
        move || crate::gfx::GfxForwarder::spawn(&display, shared.clone())
    });

    let audio_host: Arc<dyn bastion_audio::AudioHost> =
        ctx.params.audio_host.clone().unwrap_or_else(|| Arc::new(bastion_audio::PulseHost));
    let playback_opts = bastion_audio::PlaybackOptions {
        device: p.audio.output_device.clone(),
        latency: Duration::from_millis(u64::from(p.audio.playback_latency_ms.clamp(20, 1000))),
    };
    if p.audio.playback {
        let state = ironrdp_rdpsnd::client::RdpsndDvcState::new(Box::new(bastion_audio::PulsePlayback::new(
            playback_opts.clone(),
        )));
        let (a, b) = (state.clone(), state);
        drdynvc = drdynvc
            .with_dynamic_channel_factory(ironrdp_rdpsnd::client::DVC_CHANNEL_NAME, move || a.channel())
            .with_dynamic_channel_factory(ironrdp_rdpsnd::client::LOSSY_DVC_CHANNEL_NAME, move || b.lossy_channel());
    }
    // With a UDP tunnel, Windows asks for device redirection again as a dynamic channel and
    // starts no audio output until it gets one (see `svc_dvc`). Offered whenever the static
    // RDPDR is attached below, with the same folder sharing.
    if p.drive.enabled || p.audio.playback || p.audio.microphone || p.camera.enabled {
        let profile = p.clone();
        let client_name = ctx.params.client_name.clone();
        drdynvc = drdynvc.with_dynamic_channel_factory("rdpdr", move || {
            let drive = profile.drive.enabled.then(|| drive_channel(&profile, &client_name).ok()).flatten();
            let rdpdr = drive.unwrap_or_else(|| {
                ironrdp_rdpdr::Rdpdr::new(Box::new(ironrdp_rdpdr::NoopRdpdrBackend), client_name.clone())
            });
            crate::svc_dvc::SvcOverDvc::new("rdpdr", rdpdr)
        });
    }
    // Microphone and camera both push data produced on their own threads through this uplink.
    if p.camera.enabled {
        let host = ctx.params.camera_host.clone().unwrap_or_else(bastion_camera::default_host);
        let tx = uplink.camera;
        let uplink: bastion_camera::SampleUplink = Arc::new(move |id, msgs| {
            tx.send((id, msgs)).map_err(|_| ironrdp_pdu::pdu_other_err!("camera uplink closed"))
        });
        match bastion_camera::camera_channels(host, uplink) {
            Some(cams) => {
                info!(cameras = ?cams.names, "Offering cameras to the remote computer");
                drdynvc = cams.register(drdynvc);
            }
            None => {
                info!("Camera redirection is on but no usable camera was found");
                ctx.emit(Event::Notice("No webcam found to share with the remote computer.".into()));
            }
        }
    }
    if p.audio.microphone {
        let opts = bastion_audio::CaptureOptions { device: p.audio.input_device.clone() };
        let mic_host = audio_host.clone();
        let mic_tx = uplink.mic;
        let recording = Arc::new(AtomicBool::new(false));
        // One thread limit for every reopen of the channel (the server decides how often).
        let mic_threads = bastion_audio::MicThreads::default();
        drdynvc = drdynvc.with_dynamic_channel_factory(ironrdp_rdpeai::CHANNEL_NAME, move || {
            ironrdp_rdpeai::client::RdpeaiClient::new(
                Box::new(SingleCapture::new(
                    bastion_audio::PulseCapture::with_host_and_threads(
                        mic_host.clone(),
                        opts.clone(),
                        mic_threads.clone(),
                    ),
                    recording.clone(),
                )),
                mic_uplink(mic_tx.clone()),
            )
        });
    }

    let config = ironrdp_connector::Config {
        desktop_size: DesktopSize {
            width: bw.min(crate::frame::MAX_DESKTOP_SIDE) as u16,
            height: bh.min(crate::frame::MAX_DESKTOP_SIDE) as u16,
        },
        monitor_layout: gcc.as_ref().map(|g| g.0.clone()),
        desktop_scale_factor: primary.scale,
        desktop_physical_size: primary.physical_mm,
        desktop_orientation: None,
        device_scale_factor: Some(crate::layout::device_scale(primary.scale)),
        monitor_extended_layout: gcc.map(|g| g.1),
        relative_mouse_input: false,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword {
            username: p.username.trim().to_owned(),
            password: ctx.params.password.expose().to_owned(),
        },
        domain: (!p.domain.trim().is_empty()).then(|| p.domain.trim().to_owned()),
        client_build: 18363,
        client_name: ctx.params.client_name.clone(),
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: ctx.params.keyboard_layout,
        connection_type: experience(p.display.speed).0,
        ime_file_name: String::new(),
        bitmap: Some(ironrdp_connector::BitmapConfig {
            lossy_compression: true,
            color_depth: 32,
            codecs: ironrdp_pdu::rdp::capability_sets::client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: p.audio.playback,
        enable_audio_capture: p.audio.microphone,
        performance_flags: experience(p.display.speed).1,
        license_cache: None,
        timezone_info: timezone(),
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        // Reliable UDP only: lossy UDP needs DTLS, which Bastion does not implement.
        multitransport_flags: udp.then_some(
            ironrdp_pdu::gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR
                | ironrdp_pdu::gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_PREFERRED
                | ironrdp_pdu::gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP,
        ),
        support_dyn_vc_gfx_protocol: true,
    };

    let mut connector = ClientConnector::new(config, client_addr).with_static_channel(drdynvc);

    // Static RDPSND: legacy audio path, and required by the spec for RDPDR.
    if p.audio.playback {
        connector = connector.with_static_channel(ironrdp_rdpsnd::client::Rdpsnd::new(Box::new(
            bastion_audio::PulsePlayback::with_host(audio_host.clone(), playback_opts),
        )));
    } else if p.drive.enabled {
        connector = connector.with_static_channel(ironrdp_rdpsnd::client::Rdpsnd::new(Box::new(
            ironrdp_rdpsnd::client::NoopRdpsndBackend,
        )));
    }

    if let Some(f) = cliprdr {
        connector.attach_static_channel(CliprdrClient::new(f.build_cliprdr_backend()));
    }

    // Windows only activates "Remote Audio" when the device-redirection channel (RDPDR) is
    // present, so it is always opened with audio on — with no devices if sharing is off.
    let mut rdpdr_attached = false;
    if p.drive.enabled {
        match drive_channel(p, &ctx.params.client_name) {
            Ok(rdpdr) => {
                connector.attach_static_channel(rdpdr);
                rdpdr_attached = true;
            }
            Err(e) => {
                warn!(error = %e, "Drive redirection disabled");
                ctx.emit(Event::Notice(format!("Folder sharing disabled: {e}")));
            }
        }
    }
    if !rdpdr_attached && (p.audio.playback || p.audio.microphone || p.camera.enabled) {
        connector.attach_static_channel(ironrdp_rdpdr::Rdpdr::new(
            Box::new(ironrdp_rdpdr::NoopRdpdrBackend),
            ctx.params.client_name.clone(),
        ));
    }

    connector
}

fn drive_channel(p: &Profile, client_name: &str) -> anyhow::Result<ironrdp_rdpdr::Rdpdr> {
    use ironrdp_rdpdr::RdpdrBackendFactory as _;
    let path = std::path::Path::new(p.drive.local_path.trim());
    anyhow::ensure!(path.is_dir(), "{} is not a folder", path.display());
    let product = ironrdp_rdpdr_native::backend::NixRdpdrBackendFactory::new(path.to_string_lossy().into_owned())
        .with_drive(1, p.drive.share_name.trim().to_owned())
        .build_rdpdr_backend()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (backend, drives) = product.into_parts();
    let backend: Box<dyn ironrdp_rdpdr::backend::RdpdrBackend> =
        if p.drive.read_only { Box::new(crate::drive::ReadOnlyDrive::new(backend)) } else { backend };
    info!(path = %path.display(), name = %p.drive.share_name, read_only = p.drive.read_only, "Sharing local folder with remote session");
    Ok(ironrdp_rdpdr::Rdpdr::new(backend, client_name.to_owned())
        .with_drives(Some(drives.into_iter().map(|d| d.into_parts()).collect())))
}

/// Shown (after "Connection lost:") when a write made no progress for [`WRITE_TIMEOUT`].
const WRITE_STALLED: &str = "the remote computer stopped accepting data";

/// The user-facing text for a session-level protocol error. IronRDP's detailed form contains
/// source file paths, so it goes to the log only.
fn protocol_error(e: &ironrdp_session::SessionError) -> String {
    error!(error = %format!("{e:#}"), "Protocol error");
    "The remote computer sent data Bastion could not understand. See the log for details.".to_owned()
}

type Writer = ironrdp_tokio::TokioFramed<tokio::io::WriteHalf<Erased>>;

/// Aborts a spawned task when the session loop exits (on any path).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct InputTask {
    rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<InputEvents>>>,
    queued: Arc<bastion_metrics::Stamp>,
    writer: Arc<tokio::sync::Mutex<SocketWriter<Writer>>>,
    paused: Arc<AtomicBool>,
    link: Arc<crate::link::LinkStats>,
    /// Copies of the written input for keep-active (only when it is enabled).
    seen: Option<mpsc::UnboundedSender<InputEvents>>,
    /// Tells the session loop that a write timed out (the stream is then unusable).
    stalled: Arc<tokio::sync::Notify>,
}

/// Writes user input to the socket as soon as it arrives.
///
/// This runs as its own task (on another runtime worker) because the session loop decodes
/// graphics synchronously; input handled there waited for every decode — up to hundreds of
/// milliseconds under heavy screen updates. Encoding fast-path input needs no session state
/// (the pointer is drawn locally, not into the framebuffer), so it is done here directly.
async fn input_task(t: InputTask) {
    use ironrdp_pdu::input::fast_path::FastPathInput;
    let mut rx = t.rx.lock().await;
    // Input typed while (re)connecting is stale; don't replay it into the new session.
    while rx.try_recv().is_ok() {}
    let _ = t.queued.take();
    let mut bytes = Vec::new();
    while let Some(mut batch) = rx.recv().await {
        // Everything already queued goes out in one write (same order).
        while let Ok(more) = rx.try_recv() {
            batch.extend(more);
        }
        let waited = t.queued.take().unwrap_or_default();
        let since = std::time::Instant::now().checked_sub(waited);
        if t.paused.load(Ordering::Acquire) {
            continue;
        }
        bastion_metrics::INPUT_BATCHES.incr();
        bastion_metrics::INPUT_QUEUE.record(waited);
        bytes.clear();
        for chunk in batch.chunks(FastPathInput::MAX_EVENTS) {
            match FastPathInput::new(chunk.to_vec())
                .map_err(|e| e.to_string())
                .and_then(|pdu| ironrdp_core::encode_vec(&pdu).map_err(|e| e.to_string()))
            {
                Ok(frame) => bytes.extend_from_slice(&frame),
                Err(e) => warn!(error = %e, "Cannot encode input"),
            }
        }
        if bytes.is_empty() {
            continue;
        }
        let started = std::time::Instant::now();
        // The stall timeout starts once the lock is held, so input queued behind a long (but
        // progressing) clipboard write is not mistaken for a dead connection.
        match write_frame_to(&t.writer, &bytes, WRITE_TIMEOUT).await {
            Ok(()) => {}
            Err(WriteFailure::Io(e)) => {
                // The session loop notices the broken connection on its next read.
                debug!(error = %e, "Input write failed");
                return;
            }
            Err(WriteFailure::Stalled | WriteFailure::Torn) => {
                // The remote computer stopped reading; a half-written frame cannot be recovered.
                t.stalled.notify_one();
                return;
            }
        }
        bastion_metrics::NET_WRITE.since(started);
        bastion_metrics::NET_TX.add(bytes.len() as u64);
        t.link.add_tx(bytes.len());
        if let Some(t) = since {
            // Queued by the UI → encoded → written to the socket.
            bastion_metrics::INPUT_LATENCY.since(t);
        }
        if let Some(seen) = &t.seen {
            let _ = seen.send(batch);
        }
    }
}

/// Copies the changed regions from the decoder image into the shared framebuffer.
///
/// `exact` are IronRDP's per-update damage regions; `union` (their bounding box, which can
/// span both monitors) is only used when there are none.
/// The remote desktop's current size. With the graphics pipeline that is the size of its last
/// `ResetGraphics` (kept in the shared frame), which can differ from the connection-time
/// image after a monitor change.
fn desktop_size(ctx: &EngineCtx, image: &DecodedImage) -> (u16, u16) {
    if ctx.gfx_active.load(Ordering::Acquire) {
        let f = ctx.frame.lock();
        if let (Ok(w), Ok(h)) = (u16::try_from(f.width), u16::try_from(f.height))
            && w > 0
            && h > 0
        {
            return (w, h);
        }
    }
    (image.width(), image.height())
}

fn publish(
    ctx: &EngineCtx,
    image: &DecodedImage,
    union: &ironrdp_pdu::geometry::InclusiveRectangle,
    exact: &[ironrdp_pdu::geometry::InclusiveRectangle],
) {
    let to_rect = |r: &ironrdp_pdu::geometry::InclusiveRectangle| Rect {
        x: u32::from(r.left),
        y: u32::from(r.top),
        w: u32::from(r.right.saturating_sub(r.left)) + 1,
        h: u32::from(r.bottom.saturating_sub(r.top)) + 1,
    };
    if ctx.gfx_active.load(Ordering::Acquire) {
        // The pipeline owns the frame and its size; a legacy update sized from the connection
        // would resize it back. Windows sends none once the pipeline is up.
        let f = ctx.frame.lock();
        if (f.width, f.height) != (u32::from(image.width()), u32::from(image.height())) {
            debug!("Skipping a legacy bitmap update while the graphics pipeline is active");
            return;
        }
    }
    let rects: Vec<Rect> = if exact.is_empty() { vec![to_rect(union)] } else { exact.iter().map(to_rect).collect() };
    let started = std::time::Instant::now();
    let copied = ctx.frame.update_rects(image.data(), u32::from(image.width()), u32::from(image.height()), &rects);
    bastion_metrics::FRAME_PUBLISH.since(started);
    bastion_metrics::FRAME_UPDATES.incr();
    bastion_metrics::FRAME_PIXELS.add(copied);
    if !ctx.frame.needs_present.swap(true, Ordering::AcqRel) {
        (ctx.waker)();
    }
}

async fn active_session(
    ctx: &EngineCtx,
    (conn, framed, mic_rx, tunnel): Connected,
    cmd_rx: &mut mpsc::UnboundedReceiver<Command>,
    udp_ok: &mut bool,
    cookie: &mut Option<ServerAutoReconnect>,
    layout: &DesktopLayout,
) -> SessionEnd {
    let (mut reader, writer) = split_tokio_framed(framed);
    // Shared with the input task; each write holds the lock only for that write.
    let writer = Arc::new(tokio::sync::Mutex::new(SocketWriter::new(writer)));
    let input_paused = Arc::new(AtomicBool::new(false));
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<InputEvents>();
    let size = conn.desktop_size;
    if let Err(message) = check_desktop_size(size.width, size.height) {
        return SessionEnd::Fatal(message);
    }
    let mut cancel = ctx.cancel.clone();
    let write_stalled = Arc::new(tokio::sync::Notify::new());
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    let activation = conn.activation_factory;
    let (refresh_rect, suppress_output) = (conn.refresh_rect_support, conn.suppress_output_support);
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: conn.static_channels,
        user_channel_id: conn.user_channel_id,
        io_channel_id: conn.io_channel_id,
        message_channel_id: conn.message_channel_id,
        share_id: conn.share_id,
        compression_type: conn.compression_type,
        enable_server_pointer: conn.enable_server_pointer,
        pointer_software_rendering: conn.pointer_software_rendering,
    }
    .build();
    ctx.emit(Event::Status(Status::Connected { width: size.width, height: size.height }));
    // Soft-Sync may now move dynamic channels onto the UDP tunnel.
    let (udp_tx, mut udp_rx) = match tunnel.map(crate::udp::UdpTunnel::split) {
        Some((tx, rx)) => match stage.enable_reliable_udp_dvc_tunnel() {
            Ok(()) => (Some(tx), Some(rx)),
            Err(e) => {
                warn!(error = %e, "Cannot use the UDP tunnel; staying on TCP");
                (None, None)
            }
        },
        None => (None, None),
    };
    let mut udp_open = udp_rx.is_some();
    ctx.link.set_udp(udp_open);

    let mut mic_rx = mic_rx;
    let mut housekeeping = tokio::time::interval(Duration::from_secs(5));
    let mut current_layout = layout.clone();
    let mut keep_active = ctx.params.profile.keep_active.interval().map(|i| {
        info!(interval_secs = i.as_secs(), "Keep-active enabled");
        KeepActive::new(i, tokio::time::Instant::now())
    });
    let _input = AbortOnDrop(tokio::spawn(input_task(InputTask {
        rx: ctx.input_rx.clone(),
        queued: ctx.input_queued.clone(),
        writer: writer.clone(),
        paused: input_paused.clone(),
        link: ctx.link.clone(),
        seen: keep_active.is_some().then_some(seen_tx),
        stalled: write_stalled.clone(),
    })));
    // Only polled when keep-active is enabled; the far-future fallback is never reached.
    let idle_deadline = |k: &Option<KeepActive>| {
        k.as_ref().map_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400), KeepActive::deadline)
    };

    macro_rules! write_frame {
        ($bytes:expr) => {{
            let bytes: Vec<u8> = $bytes;
            if !bytes.is_empty() {
                let started = std::time::Instant::now();
                let write = write_frame_to(&writer, &bytes, WRITE_TIMEOUT);
                // The stall limit is inside the write; this only adds Disconnect.
                match bounded(&mut cancel, Duration::MAX, write).await {
                    Ok(Ok(())) => {}
                    Ok(Err(WriteFailure::Io(e))) => return SessionEnd::NetworkError(format!("write failed: {e}")),
                    Ok(Err(WriteFailure::Stalled | WriteFailure::Torn)) => {
                        return SessionEnd::NetworkError(WRITE_STALLED.into());
                    }
                    // Disconnect wins over a write the remote computer is not accepting.
                    Err(Interrupted::Cancelled) => return SessionEnd::UserClosed,
                    Err(Interrupted::TimedOut) => return SessionEnd::NetworkError(WRITE_STALLED.into()),
                }
                bastion_metrics::NET_WRITE.since(started);
                bastion_metrics::NET_TX.add(bytes.len() as u64);
                ctx.link.add_tx(bytes.len());
            }
        }};
    }
    macro_rules! session_try {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return SessionEnd::Fatal(protocol_error(&e)),
            }
        };
    }
    use ironrdp_session::SessionErrorExt as _;
    // Dynamic-channel messages go wherever Soft-Sync put their channel: the UDP tunnel or TCP.
    macro_rules! send_dvc {
        ($batch:expr) => {{
            let batch: ironrdp_dvc::DvcMessageBatch = $batch;
            match (&udp_tx, stage.dvc_tunnel_for_channel(batch.channel_id())) {
                (Some(tx), Some(_)) => {
                    for m in batch.into_messages() {
                        let bytes =
                            session_try!(m.encode_unframed_pdu().map_err(ironrdp_session::SessionError::encode));
                        ctx.link.add_tx(bytes.len());
                        // A closed tunnel is noticed (and handled) by its receiving branch.
                        let _ = tx.send(bytes);
                    }
                }
                _ => write_frame!(session_try!(stage.encode_dvc_messages(batch.into_messages()))),
            }
        }};
    }
    macro_rules! dvc_batch {
        ($channel:expr, $msgs:expr) => {
            session_try!(
                ironrdp_dvc::DvcMessageBatch::try_new($channel, $msgs).map_err(ironrdp_session::SessionError::pdu)
            )
        };
    }

    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = match frame {
                    Ok(f) => f,
                    Err(e) => return SessionEnd::NetworkError(e.to_string()),
                };
                bastion_metrics::NET_PDUS.incr();
                bastion_metrics::NET_RX.add(payload.len() as u64);
                ctx.link.add_rx(payload.len());
                let started = std::time::Instant::now();
                let out = session_try!(stage.process(&mut image, action, &payload, reader.last_read_at()));
                bastion_metrics::RDP_PROCESS.since(started);
                out
            }
            () = write_stalled.notified() => return SessionEnd::NetworkError(WRITE_STALLED.into()),
            Some((channel, msgs)) = async { match mic_rx.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                send_dvc!(dvc_batch!(channel, msgs));
                Vec::new()
            }
            pdu = async { match udp_rx.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } }, if udp_open => {
                match pdu {
                    Some(payload) => {
                        bastion_metrics::NET_PDUS.incr();
                        ctx.link.add_rx(payload.len());
                        let started = std::time::Instant::now();
                        let (batch, out) = session_try!(stage.process_dvc_tunnel(
                            &mut image,
                            ironrdp_dvc::pdu::SoftSyncTunnelType::RELIABLE_UDP,
                            &payload
                        ));
                        bastion_metrics::RDP_PROCESS.since(started);
                        // Everything answering tunnel traffic goes back on the tunnel, including
                        // the reply for a channel just declined or closed (no longer "on" it).
                        if let Some(tx) = &udp_tx {
                            for m in batch.into_messages() {
                                let bytes = session_try!(m.encode_unframed_pdu().map_err(ironrdp_session::SessionError::encode));
                                ctx.link.add_tx(bytes.len());
                                let _ = tx.send(bytes);
                            }
                        }
                        out
                    }
                    None => {
                        udp_open = false;
                        ctx.link.set_udp(false);
                        if stage.reliable_udp_dvc_tunnel_in_use() {
                            // Channels moved to UDP cannot move back: reconnect, over TCP only.
                            *udp_ok = false;
                            return SessionEnd::NetworkError("the UDP connection was lost".into());
                        }
                        let _ = stage.disable_reliable_udp_dvc_tunnel();
                        warn!("UDP tunnel closed before it was used; continuing on TCP");
                        Vec::new()
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return SessionEnd::UserClosed };
                match cmd {
                    Command::Input(events) => {
                        // Normally routed straight to the input task by `SessionHandle::send`.
                        let _ = ctx.input_tx.send(events);
                        Vec::new()
                    }
                    Command::Disconnect => {
                        let out = stage.graceful_shutdown().unwrap_or_default();
                        for o in out {
                            if let ActiveStageOutput::ResponseFrame(f) = o {
                                let goodbye = write_frame_to(&writer, &f, SHUTDOWN_WRITE_TIMEOUT);
                                let _ = tokio::time::timeout(SHUTDOWN_WRITE_TIMEOUT, goodbye).await;
                            }
                        }
                        return SessionEnd::UserClosed;
                    }
                    Command::Layout(new) => {
                        let new = new.normalized();
                        if new == current_layout {
                            Vec::new()
                        } else {
                            let batch = match (new.is_multi(), new.display_control()) {
                                (true, Some(dc)) => stage.prepare_monitor_layout(&dc),
                                _ => {
                                    let m = new.primary();
                                    stage.prepare_resize(m.width, m.height, Some(m.scale), m.physical_mm)
                                }
                            };
                            match batch {
                                Some(b) => {
                                    debug!(layout = ?new, "Sent display layout update");
                                    current_layout = new;
                                    send_dvc!(session_try!(b));
                                    Vec::new()
                                }
                                // Server doesn't support dynamic resize: reconnect at the new size.
                                None => return SessionEnd::ReconnectWithLayout(new),
                            }
                        }
                    }
                    Command::Clipboard(msg, _sent) => {
                        // `_sent` tells the clipboard worker when this response has really left
                        // for the socket (or was dropped), so it bounds what it queues behind a
                        // slow link.
                        let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                        let msgs = match msg {
                            ClipboardMessage::SendInitiateCopy(f) => c.initiate_copy(&f),
                            ClipboardMessage::SendInitiateFileCopy(f) => c.initiate_file_copy(f),
                            ClipboardMessage::SendFormatData(r) => c.submit_format_data(r),
                            ClipboardMessage::SendInitiatePaste(id) => c.initiate_paste(id),
                            ClipboardMessage::SendFileContentsRequest(r) => c.request_file_contents(r),
                            ClipboardMessage::SendFileContentsResponse(r) => c.submit_file_contents(r),
                            ClipboardMessage::Error(e) => {
                                if let Some(notice) = bastion_clipboard::ClipboardNotice::of(&*e) {
                                    ctx.emit(Event::Notice(notice.to_string()));
                                    continue;
                                }
                                warn!(error = %e, "Clipboard backend error");
                                continue;
                            }
                        };
                        match msgs {
                            Ok(m) => write_frame!(session_try!(stage.process_svc_processor_messages(m))),
                            Err(e) => warn!(error = %e, "Clipboard PDU error"),
                        }
                        Vec::new()
                    }
                    Command::RefreshScreen => {
                        let (w, h) = desktop_size(ctx, &image);
                        for f in stage.request_full_redraw(w, h, refresh_rect, suppress_output).unwrap_or_default() {
                            write_frame!(f);
                        }
                        Vec::new()
                    }
                    Command::CertificateDecision { .. } => Vec::new(),
                    Command::GfxReply(reply) => {
                        send_dvc!(dvc_batch!(reply.0, reply.1));
                        Vec::new()
                    }
                    Command::GfxFailed(message) => return SessionEnd::Fatal(message.to_owned()),
                }
            }
            Some(events) = seen_rx.recv() => {
                // User input written by the input task: keep-active only needs to know about it.
                if let Some(k) = keep_active.as_mut() {
                    k.on_input(&events, tokio::time::Instant::now());
                }
                Vec::new()
            }
            () = tokio::time::sleep_until(idle_deadline(&keep_active)), if keep_active.is_some() => {
                let Some(k) = keep_active.as_mut() else { continue };
                let events = k.nudge(desktop_size(ctx, &image), tokio::time::Instant::now());
                debug!("Idle: nudging the remote mouse to keep the session active");
                session_try!(stage.process_fastpath_input(&mut image, &events))
            }
            _ = housekeeping.tick() => {
                if let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>()
                    && let Ok(m) = c.drive_timeouts() {
                        write_frame!(session_try!(stage.process_svc_processor_messages(m)));
                    }
                Vec::new()
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(f) => write_frame!(f),
                ActiveStageOutput::GraphicsUpdate(r) => publish(ctx, &image, &r, &stage.take_damage_regions()),
                ActiveStageOutput::PointerDefault => ctx.emit(Event::Pointer(PointerEvent::Default)),
                ActiveStageOutput::PointerHidden => ctx.emit(Event::Pointer(PointerEvent::Hidden)),
                ActiveStageOutput::PointerPosition { x, y } => {
                    if let Some(k) = keep_active.as_mut() {
                        k.on_server_pointer(x, y);
                    }
                    ctx.emit(Event::Pointer(PointerEvent::Position { x, y }))
                }
                ActiveStageOutput::PointerBitmap(p) => ctx.emit(Event::Pointer(PointerEvent::Bitmap(p))),
                ActiveStageOutput::AutoReconnectCookie(c) => {
                    debug!("Received auto-reconnect cookie");
                    *cookie = Some(c);
                }
                ActiveStageOutput::AutoReconnectFailed => {
                    warn!("Server rejected auto-reconnect cookie");
                    *cookie = None;
                }
                ActiveStageOutput::LogonErrors(info) => debug!(?info, "Logon notification"),
                ActiveStageOutput::SaveSessionInfo { logon_complete } => debug!(logon_complete, "Session info"),
                ActiveStageOutput::Terminate(reason) => return SessionEnd::Graceful(reason),
                ActiveStageOutput::ServerRedirection(_) => {
                    return SessionEnd::Fatal(
                        "The server requested a redirect to another host; this is not supported yet.".into(),
                    );
                }
                ActiveStageOutput::DeactivateAll => {
                    debug!("Deactivation-reactivation sequence");
                    // No input while the connection is being re-activated.
                    input_paused.store(true, Ordering::Release);
                    let mut seq = activation.create();
                    let mut buf = WriteBuf::new();
                    // The server decides how long this takes; Disconnect and a deadline bound it.
                    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
                    loop {
                        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                        let step = single_sequence_step_read(&mut reader, &mut seq, &mut buf);
                        let written = match bounded(&mut cancel, left, step).await {
                            Ok(Ok(w)) => w,
                            Ok(Err(e)) => return SessionEnd::NetworkError(format!("reactivation: {e}")),
                            Err(Interrupted::Cancelled) => return SessionEnd::UserClosed,
                            Err(Interrupted::TimedOut) => {
                                return SessionEnd::NetworkError(
                                    "the remote computer did not finish re-activating the session".into(),
                                );
                            }
                        };
                        if written.size().is_some() {
                            write_frame!(buf.filled().to_vec());
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            static_channel_chunk_size,
                            ..
                        } = seq.connection_activation_state()
                        {
                            if let Err(message) = check_desktop_size(desktop_size.width, desktop_size.height) {
                                return SessionEnd::Fatal(message);
                            }
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.reactivate(
                                seq.io_channel_id(),
                                seq.user_channel_id(),
                                share_id,
                                enable_server_pointer,
                                false,
                                static_channel_chunk_size,
                            );
                            input_paused.store(false, Ordering::Release);
                            ctx.emit(Event::Status(Status::Connected {
                                width: desktop_size.width,
                                height: desktop_size.height,
                            }));
                            break;
                        }
                    }
                }
                ActiveStageOutput::MonitorLayout(m) => debug!(monitors = m.len(), "Server monitor layout"),
                ActiveStageOutput::AutoDetect(
                    ironrdp_pdu::rdp::autodetect::AutoDetectRequest::NetworkCharacteristicsResult {
                        base_rtt_ms,
                        bandwidth_kbps,
                        average_rtt_ms,
                        ..
                    },
                ) => {
                    debug!(average_rtt_ms, ?base_rtt_ms, ?bandwidth_kbps, "Network measured by the remote computer");
                    ctx.link.set_server_report(crate::link::ServerReport {
                        at: std::time::Instant::now(),
                        average_rtt_ms,
                        base_rtt_ms,
                        bandwidth_kbps,
                    });
                }
                other => debug!(output = ?std::mem::discriminant(&other), "Unhandled session output"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn udp_request(
        protocol: ironrdp_pdu::rdp::multitransport::RequestedProtocol,
        cookie: [u8; 16],
    ) -> ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu {
        use ironrdp_pdu::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
        ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu {
            security_header: BasicSecurityHeader { flags: BasicSecurityHeaderFlags::TRANSPORT_REQ },
            request_id: 7,
            requested_protocol: protocol,
            security_cookie: cookie,
        }
    }

    #[tokio::test]
    async fn udp_offer_is_answered_only_for_reliable_udp_on_direct_connections() {
        use ironrdp_connector::MultitransportResult;
        use ironrdp_pdu::rdp::multitransport::{MultitransportResponsePdu, RequestedProtocol};
        let decline = MultitransportResult::Failure(MultitransportResponsePdu::E_ABORT);
        let cookie = [5u8; 16];
        let (peer, key) = crate::udp::tests::server(cookie).await;
        let mut slot = None;

        // No direct peer (RD Gateway, or UDP switched off): declined without trying.
        let r = super::open_udp(&mut slot, None, "pc01", &key, udp_request(RequestedProtocol::UdpFecR, cookie)).await;
        assert_eq!(r, decline);
        // Lossy UDP needs DTLS, which Bastion does not implement.
        let r =
            super::open_udp(&mut slot, Some(peer), "pc01", &key, udp_request(RequestedProtocol::UdpFecL, cookie)).await;
        assert_eq!(r, decline);
        assert!(slot.is_none());
        // Reliable UDP to a reachable server: accepted, and the tunnel is kept.
        let r =
            super::open_udp(&mut slot, Some(peer), "pc01", &key, udp_request(RequestedProtocol::UdpFecR, cookie)).await;
        assert_eq!(r, MultitransportResult::Success);
        assert!(slot.is_some());
        // A second request while one tunnel is up is declined.
        let r =
            super::open_udp(&mut slot, Some(peer), "pc01", &key, udp_request(RequestedProtocol::UdpFecR, cookie)).await;
        assert_eq!(r, decline);
    }

    #[tokio::test]
    async fn failed_udp_setup_declines_so_the_session_stays_on_tcp() {
        use ironrdp_pdu::rdp::multitransport::RequestedProtocol;
        let (peer, key) = crate::udp::tests::server([1u8; 16]).await;
        let mut slot = None;
        // Wrong cookie: the server refuses the tunnel.
        let r =
            super::open_udp(&mut slot, Some(peer), "pc01", &key, udp_request(RequestedProtocol::UdpFecR, [2u8; 16]))
                .await;
        assert!(matches!(r, ironrdp_connector::MultitransportResult::Failure(_)));
        assert!(slot.is_none());
    }
    #[test]
    fn connection_speed_sets_network_type_and_effects() {
        use super::{ConnectionSpeed, PerformanceFlags, experience};
        use ironrdp_pdu::gcc::ConnectionType;
        let full = PerformanceFlags::ENABLE_FONT_SMOOTHING | PerformanceFlags::ENABLE_DESKTOP_COMPOSITION;
        // Auto keeps the behaviour Bastion always had.
        assert_eq!(experience(ConnectionSpeed::Auto), (ConnectionType::Autodetect, full));
        assert_eq!(experience(ConnectionSpeed::Lan), (ConnectionType::Lan, full));
        let (t, f) = experience(ConnectionSpeed::Broadband);
        assert_eq!(t, ConnectionType::BroadbandHigh);
        assert_eq!(f, full | PerformanceFlags::DISABLE_WALLPAPER);
        let (t, f) = experience(ConnectionSpeed::Low);
        assert_eq!(t, ConnectionType::BroadbandLow);
        assert!(!f.contains(PerformanceFlags::ENABLE_DESKTOP_COMPOSITION));
        assert!(f.contains(PerformanceFlags::ENABLE_FONT_SMOOTHING));
        for off in [
            PerformanceFlags::DISABLE_WALLPAPER,
            PerformanceFlags::DISABLE_FULLWINDOWDRAG,
            PerformanceFlags::DISABLE_MENUANIMATIONS,
            PerformanceFlags::DISABLE_CURSOR_SHADOW,
        ] {
            assert!(f.contains(off), "{off:?} should be set for low bandwidth");
        }
        assert!(!f.contains(PerformanceFlags::DISABLE_THEMING));
    }

    use ironrdp_pdu::nego::SecurityProtocol;
    use ironrdp_rdpeai::client::RdpeaiCaptureHandler;
    use ironrdp_rdpeai::pdu::OpenReplyPdu;
    use ironrdp_rdpeai::{AudioFormat, WaveFormat};

    use super::*;

    #[test]
    fn server_chosen_desktop_sizes_are_bounded() {
        assert!(check_desktop_size(1920, 1080).is_ok());
        assert!(check_desktop_size(1, 1).is_ok());
        assert!(check_desktop_size(8192, 8192).is_ok());
        // Multi-monitor desktops wider than one monitor: three 4K side by side, 4K + 4K + 2560.
        assert!(check_desktop_size(11_520, 2160).is_ok());
        assert!(check_desktop_size(10_240, 2160).is_ok());
        assert!(check_desktop_size(32_766, 1080).is_ok());
        for (w, h) in [
            (0, 0),
            (0, 600),
            (800, 0),
            (65535, 1),
            (1, 65535),
            (65535, 65535),
            (32_767, 1080),
            (8192, 8193),
            (16_384, 16_384),
        ] {
            let message = check_desktop_size(w, h).expect_err("must be refused");
            assert!(message.contains("unsupported desktop size"), "{message}");
        }
    }

    #[test]
    fn only_a_negotiation_that_selected_credssp_counts_as_nla() {
        let selected =
            |selected_protocol: SecurityProtocol| ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol };
        assert!(nla_selected(&selected(SecurityProtocol::HYBRID)));
        assert!(nla_selected(&selected(SecurityProtocol::HYBRID_EX)));
        assert!(nla_selected(&selected(SecurityProtocol::SSL | SecurityProtocol::HYBRID)));
        // The downgrade: TLS only, standard RDP security, or anything else without CredSSP.
        assert!(!nla_selected(&selected(SecurityProtocol::SSL)));
        assert!(!nla_selected(&selected(SecurityProtocol::empty())));
        assert!(!nla_selected(&selected(SecurityProtocol::RDSAAD)));
        // Any other connector state is not a completed negotiation.
        assert!(!nla_selected(&ClientConnectorState::Consumed));
        assert!(!nla_selected(&ClientConnectorState::BasicSettingsExchangeSendInitial {
            selected_protocol: SecurityProtocol::HYBRID
        }));
        assert!(!NLA_REQUIRED.contains(".rs"), "{NLA_REQUIRED}");
    }

    #[test]
    fn short_lived_sessions_use_up_reconnect_attempts() {
        // A server that accepts and then drops: every cycle is one more attempt.
        let mut attempt = 0;
        for expected in 1..=5 {
            attempt = attempt_after_drop(attempt, Duration::from_millis(300));
            assert_eq!(attempt, expected);
        }
        assert_eq!(attempt_after_drop(19, STABLE_SESSION - Duration::from_millis(1)), 20);
        assert_eq!(attempt_after_drop(u32::MAX, Duration::ZERO), u32::MAX);
        // A session that really worked starts the count again.
        assert_eq!(attempt_after_drop(19, STABLE_SESSION), 1);
        assert_eq!(attempt_after_drop(0, Duration::from_secs(3600)), 1);
    }

    /// A session writer whose peer never reads (and has a 16-byte receive buffer).
    fn stuck_writer() -> (tokio::sync::Mutex<SocketWriter<Writer>>, tokio::io::DuplexStream) {
        writer_with_buffer(16)
    }

    fn writer_with_buffer(peer_buffer: usize) -> (tokio::sync::Mutex<SocketWriter<Writer>>, tokio::io::DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(peer_buffer);
        let framed: Framed = ironrdp_tokio::TokioFramed::new(Box::new(ours) as Erased);
        let (_reader, writer) = split_tokio_framed(framed);
        (tokio::sync::Mutex::new(SocketWriter::new(writer)), theirs)
    }

    #[tokio::test]
    async fn disconnect_interrupts_a_write_the_peer_is_not_reading() {
        let (writer, _peer) = stuck_writer();
        let (cancel_tx, mut cancel) = watch::channel(false);
        let bytes = vec![0u8; 4096];
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = cancel_tx.send(true);
        });
        let write = write_frame_to(&writer, &bytes, Duration::from_secs(60));
        let result = bounded(&mut cancel, Duration::MAX, write).await;
        assert_eq!(result.map(|r| r.is_ok()), Err(Interrupted::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(10));
        // The frame was cut short: nothing may follow it on the stream.
        assert!(matches!(write_frame_to(&writer, b"x", Duration::from_secs(60)).await, Err(WriteFailure::Torn)));
    }

    #[tokio::test]
    async fn dropping_the_session_handle_counts_as_disconnect() {
        let (writer, _peer) = stuck_writer();
        let (cancel_tx, mut cancel) = watch::channel(false);
        drop(cancel_tx);
        let bytes = vec![0u8; 4096];
        let write = write_frame_to(&writer, &bytes, Duration::from_secs(60));
        let result = bounded(&mut cancel, Duration::MAX, write).await;
        assert_eq!(result.map(|r| r.is_ok()), Err(Interrupted::Cancelled));
    }

    #[tokio::test]
    async fn a_stuck_write_times_out() {
        let (writer, _peer) = stuck_writer();
        let bytes = vec![0u8; 4096];
        let result = write_frame_to(&writer, &bytes, Duration::from_millis(50)).await;
        assert!(matches!(result, Err(WriteFailure::Stalled)), "{result:?}");
        // A stalled stream is never written to again (the input task and session loop share it).
        let again = write_frame_to(&writer, b"x", Duration::from_secs(60)).await;
        assert!(matches!(again, Err(WriteFailure::Torn)), "{again:?}");
    }

    #[tokio::test]
    async fn a_slow_but_progressing_write_is_not_a_stall() {
        // A large clipboard response on a slow link: 1 MiB read 4 KiB per 2 ms takes over half
        // a second, longer than the 200 ms stall limit, but data keeps moving the whole time.
        let (writer, mut peer) = writer_with_buffer(4096);
        let reader = tokio::spawn(async move {
            let mut got = 0usize;
            let mut buf = vec![0u8; 4096];
            while let Ok(n @ 1..) = tokio::io::AsyncReadExt::read(&mut peer, &mut buf).await {
                got += n;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            got
        });
        let bytes = vec![7u8; 1024 * 1024];
        let limit = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = write_frame_to(&writer, &bytes, limit).await;
        assert!(result.is_ok(), "{result:?}");
        assert!(started.elapsed() > limit, "test premise: the whole write outlasts the limit");
        drop(writer);
        assert_eq!(reader.await.unwrap(), bytes.len());
    }

    #[tokio::test]
    async fn a_write_that_can_complete_still_goes_out_after_disconnect() {
        // The goodbye and anything already queued must not be lost just because the flag is set.
        let (writer, mut theirs) = writer_with_buffer(1024);
        let (cancel_tx, mut cancel) = watch::channel(false);
        cancel_tx.send(true).unwrap();
        let write = write_frame_to(&writer, b"hello", Duration::from_secs(60));
        assert!(matches!(bounded(&mut cancel, Duration::MAX, write).await, Ok(Ok(()))));
        let mut got = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut theirs, &mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    fn mic_messages(pdu: Vec<ironrdp_rdpeai::pdu::RdpeaiPdu>) -> Vec<SvcMessage> {
        let msgs = pdu.into_iter().map(|p| Box::new(p) as ironrdp_dvc::DvcMessage).collect();
        ironrdp_dvc::encode_dvc_messages(7, msgs, ironrdp_svc::ChannelFlags::empty()).unwrap()
    }

    /// What the capture thread sends for one packet (the size makes the Data PDU span chunks).
    fn mic_audio() -> Vec<SvcMessage> {
        use ironrdp_rdpeai::pdu::{DataPdu, RdpeaiPdu};
        mic_messages(vec![RdpeaiPdu::DataIncoming, RdpeaiPdu::Data(DataPdu::new(vec![1; 4000]))])
    }

    fn mic_format_change() -> Vec<SvcMessage> {
        use ironrdp_rdpeai::pdu::{FormatChangePdu, RdpeaiPdu};
        mic_messages(vec![RdpeaiPdu::FormatChange(FormatChangePdu::new(1))])
    }

    #[test]
    fn microphone_audio_is_told_apart_from_control_pdus() {
        assert!(is_mic_audio(&mic_audio()));
        assert!(!is_mic_audio(&mic_format_change()));
        assert!(!is_mic_audio(&[]));
    }

    #[test]
    fn microphone_uplink_drops_packets_instead_of_growing() {
        let (tx, mut rx) = uplink();
        let mut send = mic_uplink(tx.mic.clone());
        // Nothing drains the queue (the session loop is stuck): ten times its capacity arrives.
        for _ in 0..MIC_UPLINK_CAPACITY * 10 {
            send(7, mic_audio()).expect("a full queue is not an error for the capture thread");
        }
        let mut queued = 0;
        while rx.mic.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, MIC_UPLINK_CAPACITY);
        // (try_recv bypasses the counter MicRx::recv keeps; reset it as recv would have.)
        rx.queued_audio.store(0, Ordering::Release);
        // Drained again: packets flow again.
        send(7, mic_audio()).unwrap();
        assert!(rx.mic.try_recv().is_ok());
        // Once the session is gone the capture side is told to stop.
        drop(rx);
        assert!(send(7, mic_audio()).is_err());
    }

    #[tokio::test]
    async fn a_full_microphone_queue_still_carries_the_format_change_confirmation() {
        let (tx, mut rx) = uplink();
        let mut send = mic_uplink(tx.mic.clone());
        for _ in 0..MIC_UPLINK_CAPACITY {
            send(7, mic_audio()).unwrap();
        }
        // The queue is full of audio when the server changes the format.
        send(7, mic_format_change()).unwrap();
        send(7, mic_audio()).unwrap(); // dropped
        let mut got = Vec::new();
        while let Ok(Some((_, msgs))) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            got.push(is_mic_audio(&msgs));
        }
        assert_eq!(got.len(), MIC_UPLINK_CAPACITY + 1);
        assert_eq!(got.last(), Some(&false), "the confirmation goes out, behind the old-format audio");
        // Draining through `recv` frees the audio budget again.
        send(7, mic_audio()).unwrap();
        assert!(is_mic_audio(&rx.recv().await.unwrap().1));
    }

    #[tokio::test]
    async fn uplink_delivers_microphone_and_camera_data() {
        let (tx, mut rx) = uplink();
        mic_uplink(tx.mic.clone())(1, mic_audio()).unwrap();
        tx.camera.send((2, Vec::new())).unwrap();
        let mut ids = vec![rx.recv().await.unwrap().0, rx.recv().await.unwrap().0];
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[derive(Default)]
    struct FakeCapture {
        opens: Arc<Mutex<u32>>,
        fail: bool,
    }

    impl RdpeaiCaptureHandler for FakeCapture {
        fn supported_formats(&self) -> &[AudioFormat] {
            &[]
        }
        fn open(
            &mut self,
            _: &AudioFormat,
            _: &AudioFormat,
            _: usize,
            _: ironrdp_rdpeai::client::AudioPacketSink,
        ) -> i32 {
            *self.opens.lock().unwrap() += 1;
            if self.fail { OpenReplyPdu::E_FAIL } else { OpenReplyPdu::S_OK }
        }
        fn set_format(&mut self, _: &AudioFormat, _: usize) -> bool {
            true
        }
        fn close(&mut self) {}
    }

    fn pcm() -> AudioFormat {
        AudioFormat {
            format: WaveFormat::PCM,
            n_channels: 2,
            n_samples_per_sec: 44_100,
            n_avg_bytes_per_sec: 176_400,
            n_block_align: 4,
            bits_per_sample: 16,
            data: None,
        }
    }

    fn open(c: &mut SingleCapture<FakeCapture>) -> i32 {
        c.open(&pcm(), &pcm(), 4096, Box::new(|_| {}))
    }

    #[test]
    fn only_one_audio_input_channel_records_at_a_time() {
        let busy = Arc::new(AtomicBool::new(false));
        let opens = Arc::new(Mutex::new(0));
        let instance = || SingleCapture::new(FakeCapture { opens: opens.clone(), fail: false }, busy.clone());
        let mut first = instance();
        let mut others: Vec<_> = (0..300).map(|_| instance()).collect();

        assert_eq!(open(&mut first), OpenReplyPdu::S_OK);
        // A server opening hundreds of channels gets one capture stream, not hundreds.
        for other in &mut others {
            assert_eq!(open(other), OpenReplyPdu::E_FAIL);
        }
        assert_eq!(*opens.lock().unwrap(), 1, "refused channels must not reach the capture device");
        // Re-opening the recording channel itself is still allowed.
        assert_eq!(open(&mut first), OpenReplyPdu::S_OK);

        // Closing a refused channel must not free the slot it never held.
        others[0].close();
        assert_eq!(open(&mut others[1]), OpenReplyPdu::E_FAIL);

        first.close();
        assert_eq!(open(&mut others[1]), OpenReplyPdu::S_OK);
        // A channel that goes away while recording (Windows reopens channels at logon) frees it too.
        drop(others);
        assert_eq!(open(&mut first), OpenReplyPdu::S_OK);
    }

    #[test]
    fn a_failed_open_does_not_block_the_microphone() {
        let busy = Arc::new(AtomicBool::new(false));
        let mut broken = SingleCapture::new(FakeCapture { fail: true, ..Default::default() }, busy.clone());
        assert_eq!(open(&mut broken), OpenReplyPdu::E_FAIL);
        let mut working = SingleCapture::new(FakeCapture::default(), busy);
        assert_eq!(open(&mut working), OpenReplyPdu::S_OK);
    }

    #[test]
    fn protocol_errors_shown_to_the_user_have_no_source_paths() {
        use ironrdp_session::SessionErrorExt as _;
        let e = ironrdp_session::SessionError::reason("fast-path", "bad update");
        // What the old message was built from does contain this file's path.
        assert!(format!("{e:#}").contains(".rs:"), "test premise: {e:#}");
        let shown = protocol_error(&e);
        assert!(!shown.contains(".rs") && !shown.contains('/') && !shown.contains("fast-path"), "{shown}");
        assert!(shown.contains("See the log"), "{shown}");
        assert!(!WRITE_STALLED.contains('/'));
    }

    /// Passes everything to the system allocator, and records whether one watched block was
    /// all zeroes when it was freed (so a test can tell wiping from merely dropping).
    mod watch_alloc {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

        pub struct WatchingAlloc;
        static WATCHED: AtomicUsize = AtomicUsize::new(0);
        /// 0: not freed yet, 1: freed zeroed, 2: freed with data left in it.
        pub static FREED: AtomicU8 = AtomicU8::new(0);

        /// Held by a test for as long as it watches a block (the tests run in parallel).
        pub static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

        pub fn watch(ptr: *const u8) {
            FREED.store(0, Ordering::SeqCst);
            WATCHED.store(ptr as usize, Ordering::SeqCst);
        }

        // SAFETY: every call is forwarded unchanged to `System`; the watched block is only read
        // (within its layout) before it is freed.
        unsafe impl GlobalAlloc for WatchingAlloc {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc(layout) }
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if ptr as usize == WATCHED.load(Ordering::SeqCst)
                    && WATCHED.compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
                {
                    let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                    FREED.store(if bytes.iter().all(|&b| b == 0) { 1 } else { 2 }, Ordering::SeqCst);
                }
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        #[global_allocator]
        static ALLOC: WatchingAlloc = WatchingAlloc;
    }

    #[test]
    fn the_gateway_password_copy_is_zeroed_before_it_is_freed() {
        use std::sync::atomic::Ordering::SeqCst;
        let _serial = watch_alloc::SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let gw_pass = String::from("hunter2-gateway-password");
        watch_alloc::watch(gw_pass.as_ptr());
        let target = GwTarget(ironrdp_mstsgu::GwConnectTarget {
            gw_endpoint: "gw.example:443".to_owned(),
            gw_user: "user".to_owned(),
            gw_pass,
            smart_card: None,
            server: "pc01".to_owned(),
        });
        assert_eq!(watch_alloc::FREED.load(SeqCst), 0, "still in use");
        drop(target);
        assert_eq!(watch_alloc::FREED.load(SeqCst), 1, "the password's memory must be zeroed before it is freed");
    }

    #[test]
    fn the_password_watch_tells_a_plain_drop_apart() {
        // The check above would catch a `wipe` that only frees the buffer.
        use std::sync::atomic::Ordering::SeqCst;
        let _serial = watch_alloc::SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let pass = String::from("hunter2-gateway-password");
        watch_alloc::watch(pass.as_ptr());
        drop(pass);
        assert_eq!(watch_alloc::FREED.load(SeqCst), 2);
    }

    #[test]
    fn log_gate_lets_one_message_through_per_interval() {
        let gate = LogGate::new();
        assert_eq!(gate.pass(), Some(1));
        for _ in 0..1000 {
            assert_eq!(gate.pass(), None);
        }
        // Pretend the interval has passed: the next message reports what was suppressed.
        *gate.last.lock().unwrap() = std::time::Instant::now().checked_sub(LogGate::INTERVAL);
        assert_eq!(gate.pass(), Some(1001));
    }
}
