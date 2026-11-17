//! The session engine.
//!
//! Runs on its own OS thread with a small Tokio runtime. The UI talks to it only through
//! [`SessionHandle`]: commands in (input, resize, clipboard, decisions), events out (status,
//! pointer, prompts), plus the shared framebuffer.
//!
//! Lifecycle: connect → active session → (network drop → auto-reconnect with the server's
//! auto-reconnect cookie) → … → disconnected.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::profile::Profile;
use bastion_core::secrets::Secret;
use bastion_core::trust::{EndpointKind, TrustStore};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackendFactory};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{ClientConnector, ConnectionResult, Credentials, DesktopSize, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_egfx::client::{GraphicsPipelineClient, GraphicsPipelineHandler};
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
use tokio::sync::mpsc;
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
    Clipboard(ClipboardMessage),
    /// Answer to [`Event::CertificatePrompt`].
    CertificateDecision {
        accept: bool,
    },
    RefreshScreen,
    Disconnect,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    ConnectingGateway,
    Connecting,
    Authenticating,
    Connected { width: u16, height: u16 },
    Reconnecting { attempt: u32, max: u32 },
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

pub struct SessionHandle {
    cmd: mpsc::UnboundedSender<Command>,
    events: std::sync::mpsc::Receiver<Event>,
    pub frame: Arc<SharedFrame>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SessionHandle {
    pub fn spawn(params: ConnectParams, waker: Waker) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = std::sync::mpsc::channel();
        let frame = Arc::new(SharedFrame::default());
        let ctx = EngineCtx { params, cmd_tx: cmd_tx.clone(), events: ev_tx, waker, frame: frame.clone() };
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
        Self { cmd: cmd_tx, events: ev_rx, frame, thread: Some(thread) }
    }

    pub fn send(&self, cmd: Command) {
        let _ = self.cmd.send(cmd);
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
}

impl EngineCtx {
    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
        (self.waker)();
    }
}

#[derive(Debug)]
struct ClipboardProxy(mpsc::UnboundedSender<Command>);

impl ClipboardMessageProxy for ClipboardProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let _ = self.0.send(Command::Clipboard(message));
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

async fn run(ctx: EngineCtx, mut cmd_rx: mpsc::UnboundedReceiver<Command>) {
    let p = &ctx.params.profile;
    info!(host = %p.host, port = p.port, gateway = p.gateway.as_ref().map(|g| g.host.as_str()), "Starting session");

    // Clipboard lives for the whole session so reconnects keep working.
    let clipboard = if p.clipboard.enabled {
        let opts = bastion_clipboard::ClipboardOptions {
            files: p.clipboard.files,
            max_transfer_bytes: p.clipboard.max_transfer_mb as usize * 1024 * 1024,
        };
        match bastion_clipboard::Clipboard::new(ClipboardProxy(ctx.cmd_tx.clone()), opts) {
            Ok(c) => Some(c),
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

        let result = connect(&ctx, &layout, cliprdr_factory.as_deref(), cookie.clone(), &mut cmd_rx).await;
        let (conn, framed, mic_rx) = match result {
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
        attempt = 0;
        match active_session(&ctx, conn, framed, &mut cmd_rx, mic_rx, &mut cookie, &layout).await {
            SessionEnd::ReconnectWithLayout(new) => {
                info!("Reconnecting to apply new desktop size");
                layout = new;
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
                warn!(%msg, "Connection lost; will auto-reconnect");
                attempt = 1;
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
type MicRx = mpsc::UnboundedReceiver<(u32, Vec<SvcMessage>)>;

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
    cmd_rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<(ConnectionResult, Framed, Option<MicRx>), ConnectFailure> {
    let fut = connect_inner(ctx, layout, cliprdr, cookie);
    tokio::pin!(fut);
    let timeout = tokio::time::sleep(CONNECT_TIMEOUT * 3);
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
) -> Result<(ConnectionResult, Framed, Option<MicRx>), ConnectFailure> {
    let p = &ctx.params.profile;
    let insecure = p.security.allow_insecure_tls;
    let rejected: RejectionSlot = Arc::default();
    let cert_failure = |rejected: &RejectionSlot, message: String| match rejected.lock().ok().and_then(|mut s| s.take())
    {
        Some(rej) => ConnectFailure::Certificate(Box::new(rej)),
        None => ConnectFailure::Error { message, retryable: true },
    };

    // 1. Transport: RD Gateway tunnel or direct TCP.
    let (stream, client_addr): (Erased, SocketAddr) = if let Some(gw) = &p.gateway {
        ctx.emit(Event::Status(Status::ConnectingGateway));
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
        let target = ironrdp_mstsgu::GwConnectTarget {
            gw_endpoint: endpoint.clone(),
            gw_user,
            gw_pass,
            smart_card: None,
            server: p.host.trim().to_owned(),
        };
        let (validation, callback) = if insecure {
            (ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate, None)
        } else {
            (ironrdp_tls::CertificateValidation::Strict, Some(verifier.gateway_callback()))
        };
        let gw = ironrdp_mstsgu::GwClient::connect_with_port_and_certificate_validation(
            &target,
            &ctx.params.client_name,
            p.port,
            validation,
            callback,
        );
        let (client, addr) = match tokio::time::timeout(CONNECT_TIMEOUT, gw).await {
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
        (Box::new(client), addr)
    } else {
        ctx.emit(Event::Status(Status::Connecting));
        let target = (p.host.trim(), p.port);
        let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(target)).await {
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
        };
        let _ = tcp.set_nodelay(true);
        let addr = tcp.local_addr().map_err(|e| ConnectFailure::Error { message: e.to_string(), retryable: true })?;
        (Box::new(tcp), addr)
    };

    // 2. RDP negotiation, TLS (with our verifier), CredSSP/NLA, capability exchange.
    ctx.emit(Event::Status(Status::Connecting));
    let (mic_tx, mic_rx) = mpsc::unbounded_channel();
    let mut connector = build_connector(ctx, layout, client_addr, cliprdr, mic_tx);
    if let Some(c) = cookie {
        connector = connector.with_auto_reconnect_cookie(c);
    }
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let err = |e: ironrdp_connector::ConnectorError| {
        let (message, retryable) = friendly_connector_error(&e);
        error!(error = %format!("{e:#}"), "Connection failed");
        ConnectFailure::Error { message, retryable }
    };
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await.map_err(err)?;
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
    let (tls, server_key) = crate::tls::upgrade(stream, p.host.trim(), verifier)
        .await
        .map_err(|e| cert_failure(&rejected, format!("TLS handshake with the remote computer failed: {e}")))?;
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed: Framed = ironrdp_tokio::TokioFramed::new(Box::new(tls) as Erased);

    ctx.emit(Event::Status(Status::Authenticating));
    let outcome = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        ServerName::new(p.host.trim()),
        server_key,
        None,
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
    info!(width = result.desktop_size.width, height = result.desktop_size.height, "RDP session established");
    Ok((result, framed, Some(mic_rx)))
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

#[derive(Debug)]
struct GfxHandler;
impl GraphicsPipelineHandler for GfxHandler {}

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
    mic_tx: mpsc::UnboundedSender<(u32, Vec<SvcMessage>)>,
) -> ClientConnector {
    let p = &ctx.params.profile;
    let primary = layout.primary();
    let (_, _, bw, bh) = layout.bounds();
    let gcc = layout.gcc_monitors();

    // ── Dynamic channels ──
    let mut drdynvc = DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let display = p.display.clone();
    drdynvc = drdynvc.with_dynamic_channel_factory(ironrdp_egfx::CHANNEL_NAME, move || {
        let decoder = display.h264.then(|| {
            bastion_video::create_decoder(bastion_video::DecoderOptions {
                prefer_hardware: display.hardware_decode,
                yuv420_planes: false,
            })
        });
        GraphicsPipelineClient::new(Box::new(GfxHandler), decoder.flatten())
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
    // Microphone and camera both push data produced on their own threads through this uplink.
    if p.camera.enabled {
        let host = ctx.params.camera_host.clone().unwrap_or_else(bastion_camera::default_host);
        let tx = mic_tx.clone();
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
        drdynvc = drdynvc.with_dynamic_channel_factory(ironrdp_rdpeai::CHANNEL_NAME, move || {
            let tx = mic_tx.clone();
            ironrdp_rdpeai::client::RdpeaiClient::new(
                Box::new(bastion_audio::PulseCapture::with_host(mic_host.clone(), opts.clone())),
                Box::new(move |id, msgs| {
                    tx.send((id, msgs)).map_err(|_| ironrdp_pdu::pdu_other_err!("microphone uplink closed"))
                }),
            )
        });
    }

    let config = ironrdp_connector::Config {
        desktop_size: DesktopSize { width: bw.min(8192) as u16, height: bh.min(8192) as u16 },
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
        connection_type: ironrdp_pdu::gcc::ConnectionType::Autodetect,
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
        performance_flags: PerformanceFlags::ENABLE_FONT_SMOOTHING | PerformanceFlags::ENABLE_DESKTOP_COMPOSITION,
        license_cache: None,
        timezone_info: timezone(),
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
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

/// Copies the changed rectangle from the decoder image into the shared framebuffer.
fn publish(ctx: &EngineCtx, image: &DecodedImage, r: &ironrdp_pdu::geometry::InclusiveRectangle) {
    let rect = Rect {
        x: u32::from(r.left),
        y: u32::from(r.top),
        w: u32::from(r.right.saturating_sub(r.left)) + 1,
        h: u32::from(r.bottom.saturating_sub(r.top)) + 1,
    };
    ctx.frame.update_from(image.data(), u32::from(image.width()), u32::from(image.height()), rect);
    if !ctx.frame.needs_present.swap(true, Ordering::AcqRel) {
        (ctx.waker)();
    }
}

async fn active_session(
    ctx: &EngineCtx,
    conn: ConnectionResult,
    framed: Framed,
    cmd_rx: &mut mpsc::UnboundedReceiver<Command>,
    mic_rx: Option<MicRx>,
    cookie: &mut Option<ServerAutoReconnect>,
    layout: &DesktopLayout,
) -> SessionEnd {
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let size = conn.desktop_size;
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

    let mut mic_rx = mic_rx;
    let mut housekeeping = tokio::time::interval(Duration::from_secs(5));
    let mut current_layout = layout.clone();
    let mut keep_active = ctx.params.profile.keep_active.interval().map(|i| {
        info!(interval_secs = i.as_secs(), "Keep-active enabled");
        KeepActive::new(i, tokio::time::Instant::now())
    });
    // Only polled when keep-active is enabled; the far-future fallback is never reached.
    let idle_deadline = |k: &Option<KeepActive>| {
        k.as_ref().map_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400), KeepActive::deadline)
    };

    macro_rules! write_frame {
        ($bytes:expr) => {{
            let bytes: Vec<u8> = $bytes;
            if !bytes.is_empty() {
                if let Err(e) = writer.write_all(&bytes).await {
                    return SessionEnd::NetworkError(format!("write failed: {e}"));
                }
            }
        }};
    }
    macro_rules! session_try {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return SessionEnd::Fatal(format!("Protocol error: {e:#}")),
            }
        };
    }

    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = match frame {
                    Ok(f) => f,
                    Err(e) => return SessionEnd::NetworkError(e.to_string()),
                };
                session_try!(stage.process(&mut image, action, &payload, reader.last_read_at()))
            }
            Some((_, msgs)) = async { match mic_rx.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                write_frame!(session_try!(stage.encode_dvc_messages(msgs)));
                Vec::new()
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return SessionEnd::UserClosed };
                match cmd {
                    Command::Input(events) => {
                        if let Some(k) = keep_active.as_mut() {
                            k.on_input(&events, tokio::time::Instant::now());
                        }
                        session_try!(stage.process_fastpath_input(&mut image, &events))
                    }
                    Command::Disconnect => {
                        let out = stage.graceful_shutdown().unwrap_or_default();
                        for o in out {
                            if let ActiveStageOutput::ResponseFrame(f) = o {
                                let _ = writer.write_all(&f).await;
                            }
                        }
                        return SessionEnd::UserClosed;
                    }
                    Command::Layout(new) => {
                        let new = new.normalized();
                        if new == current_layout {
                            Vec::new()
                        } else {
                            let frame = match (new.is_multi(), new.display_control()) {
                                (true, Some(dc)) => stage.encode_monitor_layout(&dc),
                                _ => {
                                    let m = new.primary();
                                    stage.encode_resize(m.width, m.height, Some(m.scale), m.physical_mm)
                                }
                            };
                            match frame {
                                Some(f) => {
                                    debug!(layout = ?new, "Sent display layout update");
                                    current_layout = new;
                                    write_frame!(session_try!(f));
                                    Vec::new()
                                }
                                // Server doesn't support dynamic resize: reconnect at the new size.
                                None => return SessionEnd::ReconnectWithLayout(new),
                            }
                        }
                    }
                    Command::Clipboard(msg) => {
                        let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                        let msgs = match msg {
                            ClipboardMessage::SendInitiateCopy(f) => c.initiate_copy(&f),
                            ClipboardMessage::SendInitiateFileCopy(f) => c.initiate_file_copy(f),
                            ClipboardMessage::SendFormatData(r) => c.submit_format_data(r),
                            ClipboardMessage::SendInitiatePaste(id) => c.initiate_paste(id),
                            ClipboardMessage::SendFileContentsRequest(r) => c.request_file_contents(r),
                            ClipboardMessage::SendFileContentsResponse(r) => c.submit_file_contents(r),
                            ClipboardMessage::Error(e) => {
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
                        for f in stage.request_full_redraw(image.width(), image.height(), refresh_rect, suppress_output).unwrap_or_default() {
                            write_frame!(f);
                        }
                        Vec::new()
                    }
                    Command::CertificateDecision { .. } => Vec::new(),
                }
            }
            () = tokio::time::sleep_until(idle_deadline(&keep_active)), if keep_active.is_some() => {
                let Some(k) = keep_active.as_mut() else { continue };
                let events = k.nudge((image.width(), image.height()), tokio::time::Instant::now());
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
                ActiveStageOutput::GraphicsUpdate(r) => publish(ctx, &image, &r),
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
                    let mut seq = activation.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = match single_sequence_step_read(&mut reader, &mut seq, &mut buf).await {
                            Ok(w) => w,
                            Err(e) => return SessionEnd::NetworkError(format!("reactivation: {e}")),
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
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.reactivate(
                                seq.io_channel_id(),
                                seq.user_channel_id(),
                                share_id,
                                enable_server_pointer,
                                false,
                                static_channel_chunk_size,
                            );
                            ctx.emit(Event::Status(Status::Connected {
                                width: desktop_size.width,
                                height: desktop_size.height,
                            }));
                            break;
                        }
                    }
                }
                ActiveStageOutput::MonitorLayout(m) => debug!(monitors = m.len(), "Server monitor layout"),
                other => debug!(output = ?std::mem::discriminant(&other), "Unhandled session output"),
            }
        }
    }
}
