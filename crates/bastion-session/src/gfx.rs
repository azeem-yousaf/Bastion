//! The graphics pipeline (MS-RDPEGFX) on a thread of its own.
//!
//! IronRDP normally runs the pipeline inside the session loop and composites its output into
//! the session's `DecodedImage`, which we then copied into the shared framebuffer. That had two
//! costs, measured on a real session:
//! - decoding (RemoteFX Progressive takes 15–100 ms per update) blocked the session loop, so
//!   audio, clipboard and every other channel waited behind it;
//! - every decoded pixel was copied twice more: into the image one byte at a time, then into
//!   the shared framebuffer (~18 ms per H.264 frame beyond the decode itself).
//!
//! IronRDP supports running the pipeline elsewhere: a [`GfxForwarder`] is registered on the
//! channel and hands each message to a `bastion-gfx` thread that owns the
//! [`GraphicsPipelineClient`]. The thread writes the compositor's output regions straight into
//! the [`SharedFrame`] (one row copy each) and sends the pipeline's replies — capabilities,
//! frame acknowledgements — back to the session loop as [`Command::GfxReply`]. Acknowledging
//! after decoding also gives the server natural flow control when we fall behind.
//!
//! Everything arriving here is chosen by the server, so the hand-off is bounded:
//! - the queue to the thread holds at most [`QUEUE_BUDGET`] bytes; beyond that the session loop
//!   waits (TCP back-pressure, as when decoding ran inline) and gives the session up if the
//!   thread makes no room for [`QUEUE_STALL`];
//! - a session has one live pipeline: a further channel retires the previous one, and at most
//!   [`MAX_PIPELINE_THREADS`] threads may still be winding down ([`Pipelines`]);
//! - a retired or closed pipeline drops what is still queued and ends after its current message,
//!   whose output (pixels and replies) it discards;
//! - log lines a server can trigger per message go through a [`LogGate`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use ironrdp_dvc::{DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_egfx::client::{GraphicsPipelineClient, GraphicsPipelineHandler};
use ironrdp_pdu::PduResult;
use ironrdp_svc::SvcMessage;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::engine::{Command, Waker};
use crate::frame::{Rect, SharedFrame};

/// Encoded pipeline replies for the session loop to send (see [`Command::GfxReply`]).
#[derive(Debug)]
pub struct GfxReply(pub(crate) u32, pub(crate) Vec<SvcMessage>);

/// What the graphics thread needs from the session.
#[derive(Clone)]
pub(crate) struct GfxShared {
    pub frame: Arc<SharedFrame>,
    pub waker: Waker,
    pub replies: mpsc::UnboundedSender<Command>,
    /// Set once the pipeline owns the framebuffer: legacy bitmap updates (sized from the
    /// connection, not from `ResetGraphics`) must not resize it any more.
    pub active: Arc<AtomicBool>,
}

/// Graphics data a session may have queued for its graphics thread. A cooperative server stays
/// far below this (it waits for frame acknowledgements); one that does not is slowed down to
/// the speed we decode at instead of being buffered without limit.
const QUEUE_BUDGET: usize = 64 << 20;
/// How long the session loop waits for room in a full queue before the session is given up
/// (the graphics thread is then stuck in one message, and so would the session be).
const QUEUE_STALL: Duration = Duration::from_secs(10);
/// Charged per queued message on top of its bytes, so empty messages are bounded too.
const JOB_OVERHEAD: usize = 64;
/// Graphics threads a session may have alive: the live pipeline plus retired ones still
/// finishing a message. Windows reopens the channel once, at logon; anything near this many
/// overlapping threads is a server opening channels in a loop.
const MAX_PIPELINE_THREADS: usize = 4;

const FRAME_SIZE_MESSAGE: &str = "The remote computer reported an unsupported desktop size.";
const STALL_MESSAGE: &str = "The remote computer sent graphics faster than they could be displayed.";
const REFUSED_MESSAGE: &str = "Too many graphics channels are open.";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn channel_error(description: &'static str) -> ironrdp_pdu::PduError {
    ironrdp_pdu::pdu_other_err!("graphics", description)
}

/// Lets a short burst of log lines through per window and counts the rest (`log.suppressed`
/// in the metrics line). For lines whose frequency the server controls — one per message,
/// channel or PDU — which would otherwise let it write to the log file as fast as it can send.
struct LogGate {
    /// Window number (upper 32 bits, 0 = never used) and lines let through in it (lower 32).
    state: AtomicU64,
}

impl LogGate {
    const BURST: u64 = 5;
    const WINDOW_SECS: u64 = 30;

    const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    fn allow(&self) -> bool {
        static START: OnceLock<Instant> = OnceLock::new();
        let window = START.get_or_init(Instant::now).elapsed().as_secs() / Self::WINDOW_SECS + 1;
        let allowed = self.allow_in(window);
        if !allowed {
            bastion_metrics::LOG_SUPPRESSED.incr();
        }
        allowed
    }

    fn allow_in(&self, window: u64) -> bool {
        let window = window & 0xFFFF_FFFF;
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let next = if current >> 32 != window {
                (window << 32) | 1
            } else if current & 0xFFFF_FFFF < Self::BURST {
                current + 1
            } else {
                return false;
            };
            match self.state.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
    }
}

/// `gated!(warn, ...)`: `tracing::warn!(...)` through a [`LogGate`] of its own.
macro_rules! gated {
    ($level:ident, $($arg:tt)+) => {{
        static GATE: LogGate = LogGate::new();
        if GATE.allow() {
            $level!($($arg)+);
        }
    }};
}

enum Job {
    Start(u32),
    Data(u32, Vec<u8>),
}

impl Job {
    fn cost(&self) -> usize {
        match self {
            Job::Start(_) => JOB_OVERHEAD,
            Job::Data(_, payload) => payload.len().saturating_add(JOB_OVERHEAD),
        }
    }
}

/// The queue was full and the graphics thread made no room in time.
#[derive(Debug, PartialEq, Eq)]
struct Stalled;

/// Messages on their way to one graphics thread, bounded by bytes.
struct Queue {
    state: Mutex<QueueState>,
    /// Signalled when a job arrives or the queue closes (the thread waits on it).
    arrived: Condvar,
    /// Signalled when a job is taken or the queue closes (the session loop waits on it).
    room: Condvar,
    budget: usize,
    /// Set by the thread when the server announced a desktop size we refuse (it also asks the
    /// session loop to end the session); later messages on the channel are refused too.
    frame_refused: AtomicBool,
}

#[derive(Default)]
struct QueueState {
    jobs: VecDeque<Job>,
    bytes: usize,
    /// Nothing more is accepted or handed out: the channel closed, the pipeline was retired,
    /// or its thread ended.
    closed: bool,
}

impl Queue {
    fn new(budget: usize) -> Self {
        Self {
            state: Mutex::default(),
            arrived: Condvar::new(),
            room: Condvar::new(),
            budget,
            frame_refused: AtomicBool::new(false),
        }
    }

    /// Queues `job`, waiting up to `patience` for room. A lone job always fits, whatever its
    /// size; a closed queue swallows it (nothing will display it any more).
    fn push(&self, job: Job, patience: Duration) -> Result<(), Stalled> {
        let cost = job.cost();
        let mut st = lock(&self.state);
        let mut deadline = None;
        loop {
            if st.closed {
                return Ok(());
            }
            if st.bytes == 0 || st.bytes.saturating_add(cost) <= self.budget {
                break;
            }
            let deadline = *deadline.get_or_insert_with(|| Instant::now() + patience);
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Stalled);
            }
            st = self.room.wait_timeout(st, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
        }
        st.bytes = st.bytes.saturating_add(cost);
        st.jobs.push_back(job);
        drop(st);
        self.arrived.notify_one();
        Ok(())
    }

    /// The next job, waiting for one; `None` once the queue is closed.
    fn pop(&self) -> Option<Job> {
        let mut st = lock(&self.state);
        loop {
            if st.closed {
                return None;
            }
            if let Some(job) = st.jobs.pop_front() {
                st.bytes = st.bytes.saturating_sub(job.cost());
                drop(st);
                self.room.notify_all();
                return Some(job);
            }
            st = self.arrived.wait(st).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Ends the pipeline: queued messages are dropped and its thread stops after the message
    /// it is in.
    fn close(&self) {
        let mut st = lock(&self.state);
        st.closed = true;
        st.jobs = VecDeque::new();
        st.bytes = 0;
        drop(st);
        self.arrived.notify_all();
        self.room.notify_all();
    }

    fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }
}

/// A session's graphics pipelines (kept in its [`SharedFrame`], which every channel of the
/// session shares). The dynamic-channel layer creates a processor for every Create Request the
/// server sends, under any channel id, and each of ours owns a thread and an H.264 decoder —
/// so they are limited here: one live pipeline, and a cap on threads still winding down.
#[derive(Default)]
pub(crate) struct Pipelines {
    current: Option<Arc<Queue>>,
    threads: usize,
}

impl std::fmt::Debug for Pipelines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipelines").field("live", &self.current.is_some()).field("threads", &self.threads).finish()
    }
}

impl Pipelines {
    /// Makes `queue` the session's pipeline and retires the previous one. `false` (nothing
    /// admitted) while too many retired threads are still alive.
    fn admit(&mut self, queue: &Arc<Queue>) -> bool {
        if let Some(previous) = self.current.take() {
            previous.close();
        }
        if self.threads >= MAX_PIPELINE_THREADS {
            return false;
        }
        self.threads += 1;
        self.current = Some(queue.clone());
        true
    }

    /// The thread of an admitted pipeline ended (or never started).
    fn finished(&mut self, queue: &Arc<Queue>) {
        self.threads = self.threads.saturating_sub(1);
        if self.current.as_ref().is_some_and(|c| Arc::ptr_eq(c, queue)) {
            self.current = None;
        }
    }
}

/// Held by the graphics thread: whichever way it ends, its queue closes (so the session loop
/// never waits on a dead thread) and its slot in [`Pipelines`] is returned.
struct ThreadExit {
    queue: Arc<Queue>,
    frame: Arc<SharedFrame>,
}

impl Drop for ThreadExit {
    fn drop(&mut self) {
        self.queue.close();
        lock(&self.frame.gfx).finished(&self.queue);
    }
}

/// Stands in for the pipeline on the dynamic channel and forwards to the graphics thread.
/// Dropping it (channel closed or session over) ends the thread.
pub(crate) struct GfxForwarder {
    /// `None`: refused (see [`Pipelines`]); the channel is then reported as unavailable.
    queue: Option<Arc<Queue>>,
}

ironrdp_core::impl_as_any!(GfxForwarder);

impl GfxForwarder {
    /// Creates the pipeline client and its thread.
    pub(crate) fn spawn(display: &bastion_core::profile::DisplaySettings, shared: GfxShared) -> Self {
        let queue = Arc::new(Queue::new(QUEUE_BUDGET));
        if !lock(&shared.frame.gfx).admit(&queue) {
            gated!(warn, "Refusing another graphics channel: too many are still open");
            return Self { queue: None };
        }
        let exit = ThreadExit { queue: queue.clone(), frame: shared.frame.clone() };
        let codecs = Arc::new(AtomicU32::new(0));
        let reset = Arc::new(AtomicBool::new(false));
        let display = display.clone();
        let spawned = std::thread::Builder::new().name("bastion-gfx".into()).spawn(move || {
            let exit = exit;
            if exit.queue.is_closed() {
                return; // Retired before it began: don't open a decoder for nothing.
            }
            // Created here: opening the H.264 decoder can take a moment.
            let client = gfx_client(&display, Some(reset.clone()), codecs.clone());
            run(&exit.queue, client, &shared, &codecs, &reset);
        });
        if let Err(e) = spawned {
            // The closure (and with it `exit`) was dropped: the queue is closed.
            gated!(warn, error = %e, "Cannot start the graphics thread");
        }
        Self { queue: Some(queue) }
    }
}

impl Drop for GfxForwarder {
    fn drop(&mut self) {
        if let Some(queue) = &self.queue {
            queue.close();
        }
    }
}

impl DvcProcessor for GfxForwarder {
    fn channel_name(&self) -> &str {
        ironrdp_egfx::CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        // An error here makes the channel layer answer the Create Request with "no listener"
        // and drop this processor, instead of leaving the server waiting on a dead channel.
        let queue = self.queue.as_ref().filter(|q| !q.is_closed()).ok_or_else(|| channel_error(REFUSED_MESSAGE))?;
        queue.push(Job::Start(channel_id), QUEUE_STALL).map_err(|Stalled| channel_error(STALL_MESSAGE))?;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let Some(queue) = &self.queue else {
            return Ok(Vec::new());
        };
        if queue.frame_refused.load(Ordering::Relaxed) {
            return Err(channel_error(FRAME_SIZE_MESSAGE));
        }
        // Blocks while the queue is over budget: the session loop stops reading, and TCP flow
        // control slows the server down to the speed graphics are decoded at.
        queue.push(Job::Data(channel_id, payload.to_vec()), QUEUE_STALL).map_err(|Stalled| {
            gated!(warn, "The graphics thread is not keeping up and its queue is full; ending the session");
            channel_error(STALL_MESSAGE)
        })?;
        Ok(Vec::new())
    }

    fn close(&mut self, _channel_id: u32) {
        if let Some(queue) = &self.queue {
            queue.close();
        }
    }
}

impl DvcClientProcessor for GfxForwarder {}

/// The pipeline's right to touch session state: held while it replies and composites. `None`
/// once the pipeline is retired or closed. A newer pipeline is admitted under the same lock
/// (and retires this one there), so a retired pipeline's output never lands after it.
fn live<'a>(queue: &Queue, shared: &'a GfxShared) -> Option<MutexGuard<'a, Pipelines>> {
    let guard = lock(&shared.frame.gfx);
    (!queue.is_closed()).then_some(guard)
}

fn run(queue: &Queue, mut client: GraphicsPipelineClient, shared: &GfxShared, codecs: &AtomicU32, reset: &AtomicBool) {
    let mut capture = Capture::from_env();
    let mut started_on = None;
    while let Some(job) = queue.pop() {
        match job {
            Job::Start(id) => match client.start(id) {
                Ok(msgs) => {
                    let Some(_live) = live(queue, shared) else { break };
                    started_on = Some(id);
                    reply(shared, id, msgs);
                }
                Err(e) => gated!(warn, error = %e, "Graphics pipeline failed to start"),
            },
            Job::Data(id, payload) => {
                if capture.as_mut().is_some_and(|c| !c.record(&payload)) {
                    warn!("Graphics recording stopped (write failed)");
                    capture = None;
                }
                let started = Instant::now();
                let result = client.process(id, &payload);
                let took = started.elapsed();
                bastion_metrics::GFX_PROCESS.record(took);
                record_codec_time(codecs.swap(0, Ordering::Relaxed), took);
                // Retired while decoding: what this message produced belongs to no one.
                let Some(_live) = live(queue, shared) else { break };
                match result {
                    Ok(msgs) => reply(shared, id, msgs),
                    Err(e) => {
                        bastion_metrics::GFX_ERRORS.incr();
                        gated!(warn, error = %e, "Graphics pipeline error");
                    }
                }
                if reset.swap(false, Ordering::Relaxed) {
                    match client.request_protocol_reset() {
                        Some(pdu) => {
                            gated!(info, "Requested a graphics stream reset");
                            reply(shared, id, vec![Box::new(pdu)]);
                        }
                        None => gated!(warn, "Graphics stream reset not possible"),
                    }
                }
                if !composite(&mut client, shared) {
                    // Nothing sensible can be shown from here on. The server may send nothing
                    // more (it waits for the acknowledgement of this frame), so end the session
                    // now rather than on its next graphics message.
                    gated!(warn, "The server announced a desktop size beyond what Bastion supports");
                    queue.frame_refused.store(true, Ordering::Relaxed);
                    let _ = shared.replies.send(Command::GfxFailed(FRAME_SIZE_MESSAGE));
                    break;
                }
            }
        }
    }
    if let Some(id) = started_on {
        client.close(id);
    }
    debug!("Graphics thread finished");
}

/// Opt-in recording of the raw graphics channel (`BASTION_GFX_CAPTURE=<folder>`), for
/// replaying real sessions in benchmarks (`examples/gfx_replay.rs`).
///
/// A recording contains the remote screen's contents, so it is never on by default, files are
/// owner-only, and nothing is sent anywhere.
///
/// Format: `BGFXCAP1`, then for each message a little-endian `u32` length and the bytes as
/// received on the channel (ZGFX-wrapped).
struct Capture {
    out: std::io::BufWriter<std::fs::File>,
}

const CAPTURE_MAGIC: &[u8; 8] = b"BGFXCAP1";

impl Capture {
    fn from_env() -> Option<Self> {
        let dir = std::path::PathBuf::from(std::env::var_os("BASTION_GFX_CAPTURE")?);
        let open = || -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::create_dir_all(&dir)?;
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let path = dir.join(format!("gfx-{}-{}.bin", stamp.as_secs(), stamp.subsec_millis()));
            let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
            Ok((path, file))
        };
        match open() {
            Ok((path, file)) => {
                gated!(warn, path = %path.display(), "Recording the graphics channel (contains screen contents)");
                let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
                std::io::Write::write_all(&mut out, CAPTURE_MAGIC).ok()?;
                Some(Self { out })
            }
            Err(e) => {
                gated!(warn, error = %e, "Cannot record the graphics channel");
                None
            }
        }
    }

    /// Appends one message; `false` if writing failed (the caller then stops recording, so a
    /// full disk is reported once rather than once per message).
    fn record(&mut self, payload: &[u8]) -> bool {
        use std::io::Write as _;
        let Ok(len) = u32::try_from(payload.len()) else {
            return false;
        };
        self.out.write_all(&len.to_le_bytes()).and_then(|()| self.out.write_all(payload)).is_ok()
    }
}

/// Totals from [`replay_capture`].
#[derive(Debug)]
pub struct ReplayStats {
    pub messages: usize,
    pub bytes: usize,
    /// Wall-clock time spent in the pipeline and compositing (excludes reading the file).
    pub busy: Duration,
    /// FNV-1a hash of the final framebuffer, to compare pipelines pixel for pixel.
    pub frame_checksum: u64,
    /// Final framebuffer size.
    pub frame_size: (u32, u32),
    /// FNV-1a hash over every updated region's pixels, in order, across the whole replay.
    pub updates_checksum: u64,
}

/// Replays a recording through the same pipeline and compositing as a live session, recording
/// the usual `gfx.*`/`frame.*` metrics. Used by `examples/gfx_replay.rs`.
pub fn replay_capture(
    path: &std::path::Path,
    display: &bastion_core::profile::DisplaySettings,
) -> anyhow::Result<ReplayStats> {
    let data = std::fs::read(path)?;
    let body = data
        .strip_prefix(CAPTURE_MAGIC.as_slice())
        .ok_or_else(|| anyhow::anyhow!("not a Bastion graphics recording"))?;
    let mut messages = Vec::new();
    let mut rest = body;
    while rest.len() >= 4 {
        let len = u32::from_le_bytes(rest[..4].try_into()?) as usize;
        anyhow::ensure!(rest.len() >= 4 + len, "truncated recording");
        messages.push(&rest[4..4 + len]);
        rest = &rest[4 + len..];
    }
    let (replies, _keep) = mpsc::unbounded_channel();
    let shared =
        GfxShared { frame: Arc::new(SharedFrame::default()), waker: Arc::new(|| {}), replies, active: Arc::default() };
    let codecs = Arc::new(AtomicU32::new(0));
    let reset = Arc::new(AtomicBool::new(false));
    let mut client = gfx_client(display, Some(reset.clone()), codecs.clone());
    client.start(1).map_err(|e| anyhow::anyhow!("start: {e}"))?;
    let mut busy = Duration::ZERO;
    let mut bytes = 0;
    let mut updates_checksum = 0xcbf2_9ce4_8422_2325_u64;
    for msg in &messages {
        bytes += msg.len();
        let started = Instant::now();
        let result = client.process(1, msg);
        let took = started.elapsed();
        bastion_metrics::GFX_PROCESS.record(took);
        record_codec_time(codecs.swap(0, Ordering::Relaxed), took);
        if let Err(e) = result {
            gated!(warn, error = %e, "Graphics pipeline error during replay");
        }
        let _ = reset.swap(false, Ordering::Relaxed);
        anyhow::ensure!(composite(&mut client, &shared), "the recording announces an unsupported desktop size");
        busy += started.elapsed();
        // The renderer would take the dirty list: hash what it would upload, then clear it.
        let mut f = shared.frame.lock();
        let stride = f.width as usize * 4;
        for r in std::mem::take(&mut f.dirty) {
            for row in r.y..r.y + r.h {
                let start = row as usize * stride + r.x as usize * 4;
                for &b in &f.data[start..start + r.w as usize * 4] {
                    updates_checksum = (updates_checksum ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
                }
            }
        }
    }
    let f = shared.frame.lock();
    let frame_checksum =
        f.data.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    let frame_size = (f.width, f.height);
    drop(f);
    Ok(ReplayStats { messages: messages.len(), bytes, busy, frame_checksum, frame_size, updates_checksum })
}

fn reply(shared: &GfxShared, channel_id: u32, msgs: Vec<DvcMessage>) {
    if msgs.is_empty() {
        return;
    }
    match ironrdp_dvc::encode_dvc_messages(channel_id, msgs, ironrdp_svc::ChannelFlags::empty()) {
        Ok(svc) => {
            let _ = shared.replies.send(Command::GfxReply(GfxReply(channel_id, svc)));
        }
        Err(e) => gated!(warn, error = %e, "Cannot encode graphics pipeline reply"),
    }
}

/// Copies what the pipeline finished since the last call into the shared framebuffer.
///
/// Returns `false` if the server reset the output to a size the shared frame refuses (the
/// pipeline itself allows up to 32766 per side, far more than a texture can hold).
fn composite(client: &mut GraphicsPipelineClient, shared: &GfxShared) -> bool {
    let reset = client.take_output_reset();
    if let Some((w, h)) = reset {
        if !shared.frame.reset(u32::from(w), u32::from(h)) {
            return false;
        }
        shared.active.store(true, Ordering::Release);
    }
    // RemoteApp windows are not used.
    let _ = client.drain_window_updates();
    let output = client.drain_output();
    if output.is_empty() && reset.is_none() {
        return true;
    }
    let started = Instant::now();
    let copied = shared.frame.apply_regions(output.iter().map(|u| {
        let r = &u.region;
        let rect = Rect {
            x: u32::from(r.left),
            y: u32::from(r.top),
            w: u32::from(r.right.saturating_sub(r.left)),
            h: u32::from(r.bottom.saturating_sub(r.top)),
        };
        (rect, u.data.as_slice())
    }));
    bastion_metrics::FRAME_PUBLISH.since(started);
    bastion_metrics::FRAME_UPDATES.incr();
    bastion_metrics::FRAME_PIXELS.add(copied);
    if !shared.frame.needs_present.swap(true, Ordering::AcqRel) {
        (shared.waker)();
    }
    true
}

/// The pipeline client with our H.264 decoder. `reset` lets the handler ask the graphics
/// thread to restart the stream (see [`GfxHandler`]); `None` disables the fast AVC420 path.
pub(crate) fn gfx_client(
    display: &bastion_core::profile::DisplaySettings,
    reset: Option<Arc<AtomicBool>>,
    codecs: Arc<AtomicU32>,
) -> GraphicsPipelineClient {
    let decoder = display.h264.then(|| {
        bastion_video::FfmpegH264Decoder::new(bastion_video::DecoderOptions {
            prefer_hardware: display.hardware_decode,
            // Must be on: every modern pipeline version (V10.x) implies AVC444, which needs the
            // YUV planes, so without them IronRDP advertises only V8/V8.1 — and Windows 10/11
            // never uses H.264 in V8.1. It then confirmed V8.1 with AVC off and sent everything
            // with CPU-decoded codecs (60–90 ms per update while video played). With V10.x
            // Windows chooses AVC420 or AVC444 itself.
            yuv420_planes: true,
            // Software first (faster for remote-desktop streams), hardware if it can't keep up.
            adaptive: true,
        })
        .map_err(|e| gated!(warn, error = %e, "H.264 decoding unavailable"))
        .ok()
        .map(|mut d| {
            if let Some(r) = &reset {
                // A graphics stream reset makes the server start over with a keyframe.
                d.set_keyframe_request(r.clone());
            }
            d
        })
    });
    let decoder = decoder.flatten();
    let planes = decoder.as_ref().map(bastion_video::FfmpegH264Decoder::yuv420_switch);
    let handler = GfxHandler { codecs, planes, avc444: false, reset };
    GraphicsPipelineClient::new(
        Box::new(handler),
        decoder.map(|d| Box::new(d) as Box<dyn ironrdp_egfx::decode::H264Decoder>),
    )
}

/// Codecs seen by the graphics handler during the message being processed (bit mask).
mod codec_bits {
    pub const AVC420: u32 = 1;
    pub const AVC444: u32 = 1 << 1;
    pub const CLEARCODEC: u32 = 1 << 2;
    pub const PLANAR: u32 = 1 << 3;
    pub const PROGRESSIVE: u32 = 1 << 4;
    pub const REMOTEFX: u32 = 1 << 5;
    pub const OTHER: u32 = 1 << 6;
}

/// The codec bit for a decoded update. Progressive tiles arrive as "uncompressed" after
/// decoding and were already marked by `on_wire_to_surface2`.
fn codec_bit(codec: ironrdp_egfx::pdu::Codec1Type, progressive_seen: bool) -> Option<u32> {
    use codec_bits as b;
    use ironrdp_egfx::pdu::Codec1Type as C;
    Some(match codec {
        C::Avc420 => b::AVC420,
        C::Avc444 | C::Avc444v2 => b::AVC444,
        C::ClearCodec => b::CLEARCODEC,
        C::Planar => b::PLANAR,
        C::RemoteFx => b::REMOTEFX,
        C::Uncompressed if progressive_seen => return None,
        _ => b::OTHER,
    })
}

/// Attributes one message's processing time to the codec that produced its graphics.
fn record_codec_time(mask: u32, d: Duration) {
    use codec_bits as b;
    let h = match mask {
        0 => return,
        b::AVC420 => &bastion_metrics::GFX_AVC420,
        b::AVC444 => &bastion_metrics::GFX_AVC444,
        b::CLEARCODEC => &bastion_metrics::GFX_CLEARCODEC,
        b::PLANAR => &bastion_metrics::GFX_PLANAR,
        b::PROGRESSIVE => &bastion_metrics::GFX_PROGRESSIVE,
        b::REMOTEFX => &bastion_metrics::GFX_REMOTEFX,
        b::OTHER => &bastion_metrics::GFX_OTHER,
        _ => &bastion_metrics::GFX_MIXED,
    };
    h.record(d);
}

#[derive(Debug)]
struct GfxHandler {
    /// Codecs used in the current message, read and cleared by the graphics thread.
    codecs: Arc<AtomicU32>,
    /// The decoder's YUV-planes switch (`None` without H.264).
    planes: Option<Arc<AtomicBool>>,
    /// The server has sent AVC444 in this session: planes stay on.
    avc444: bool,
    /// Asks the graphics thread to reset the stream.
    reset: Option<Arc<AtomicBool>>,
}

impl GfxHandler {
    fn mark(&self, bit: u32) {
        self.codecs.fetch_or(bit, Ordering::Relaxed);
    }
}

impl GraphicsPipelineHandler for GfxHandler {
    /// Only the codec is read (for metrics), so decoders may skip copying pixels for us.
    fn wants_bitmap_data(&self) -> bool {
        false
    }

    fn on_bitmap_updated(&mut self, update: &ironrdp_egfx::client::BitmapUpdate) {
        let seen = self.codecs.load(Ordering::Relaxed);
        if let Some(bit) = codec_bit(update.codec_id, seen & codec_bits::PROGRESSIVE != 0) {
            self.mark(bit);
        }
    }

    fn on_wire_to_surface2(&mut self, _pdu: &ironrdp_egfx::pdu::WireToSurface2Pdu) {
        self.mark(codec_bits::PROGRESSIVE);
    }

    fn on_solid_fill(&mut self, _pdu: &ironrdp_egfx::pdu::SolidFillPdu) {
        self.mark(codec_bits::OTHER);
    }

    fn on_surface_to_surface(&mut self, _pdu: &ironrdp_egfx::pdu::SurfaceToSurfacePdu) {
        self.mark(codec_bits::OTHER);
    }

    fn on_cache_to_surface(&mut self, _pdu: &ironrdp_egfx::pdu::CacheToSurfacePdu) {
        self.mark(codec_bits::OTHER);
    }

    fn on_capabilities_confirmed(&mut self, caps: &ironrdp_egfx::pdu::CapabilitySet) {
        use ironrdp_egfx::pdu::CapabilitySet as C;
        // Which graphics mode the server chose decides whether H.264 can be used at all.
        gated!(info, ?caps, "Graphics pipeline negotiated");
        if let Some(planes) = &self.planes {
            // Planes were needed to advertise V10.x. Windows streams AVC420 unless its "AVC444"
            // policy is on, and AVC420 is far faster through our own conversion, so turn them
            // off — but only where a later switch to AVC444 can be recovered with a protocol
            // reset (V10.3+); otherwise keep the slow-but-always-correct path.
            let resettable = matches!(
                caps,
                C::V10_3 { .. }
                    | C::V10_4 { .. }
                    | C::V10_5 { .. }
                    | C::V10_6 { .. }
                    | C::V10_6Err { .. }
                    | C::V10_7 { .. }
            );
            let fast = resettable && !self.avc444 && self.reset.is_some();
            planes.store(!fast, Ordering::Relaxed);
            debug!(fast_avc420 = fast, "H.264 conversion path chosen");
        }
    }

    fn on_unhandled_pdu(&mut self, pdu: &ironrdp_egfx::pdu::GfxPdu) {
        use ironrdp_egfx::pdu::{Codec1Type, GfxPdu};
        // With planes off IronRDP can't decode AVC444 and hands the frame to us instead. That
        // frame is lost, so switch planes on for the rest of the session and restart the stream.
        if let GfxPdu::WireToSurface1(w) = pdu
            && matches!(w.codec_id, Codec1Type::Avc444 | Codec1Type::Avc444v2)
            && !self.avc444
        {
            self.avc444 = true;
            if let Some(planes) = &self.planes {
                planes.store(true, Ordering::Relaxed);
            }
            info!("Server streams AVC444; switching to YUV planes and resetting the graphics stream");
            if let Some(r) = &self.reset {
                r.store(true, Ordering::Relaxed);
            }
        }
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        gated!(info, width, height, "Graphics output reset");
    }

    fn on_surface_created(&mut self, surface: &ironrdp_egfx::client::Surface) {
        debug!(?surface, "Graphics surface created");
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_egfx::pdu::{CapabilitySet, GfxPdu};

    use super::*;

    fn advertised(display: &bastion_core::profile::DisplaySettings) -> Vec<CapabilitySet> {
        let mut client = gfx_client(display, None, Arc::default());
        let msgs = client.start(1).expect("start");
        let bytes = ironrdp_core::encode_vec(msgs[0].as_ref()).expect("encode");
        match ironrdp_core::decode::<GfxPdu>(&bytes).expect("decode") {
            GfxPdu::CapabilitiesAdvertise(pdu) => pdu.0.iter().filter_map(|c| c.parsed().ok().flatten()).collect(),
            other => panic!("expected a capabilities advertisement, got {other:?}"),
        }
    }

    #[test]
    fn h264_advertises_modern_pipeline_versions() {
        // Windows only uses H.264 with V10.x; offering just V8.1 silently disables it.
        let display = bastion_core::profile::DisplaySettings { hardware_decode: false, ..Default::default() };
        let caps = advertised(&display);
        assert!(matches!(caps.first(), Some(CapabilitySet::V10_7 { .. })), "{caps:?}");
        assert!(caps.iter().any(|c| matches!(c, CapabilitySet::V8_1 { .. })), "V8.1 kept as fallback: {caps:?}");
    }

    #[test]
    fn without_h264_no_avc_is_advertised() {
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let caps = advertised(&display);
        assert!(!caps.iter().any(|c| matches!(c, CapabilitySet::V10_7 { .. })), "{caps:?}");
    }

    fn handler() -> (GfxHandler, Arc<AtomicBool>, Arc<AtomicBool>) {
        let planes = Arc::new(AtomicBool::new(true));
        let reset = Arc::new(AtomicBool::new(false));
        let h = GfxHandler {
            codecs: Arc::default(),
            planes: Some(planes.clone()),
            avc444: false,
            reset: Some(reset.clone()),
        };
        (h, planes, reset)
    }

    fn avc444_frame() -> GfxPdu {
        GfxPdu::WireToSurface1(ironrdp_egfx::pdu::WireToSurface1Pdu {
            surface_id: 0,
            codec_id: ironrdp_egfx::pdu::Codec1Type::Avc444,
            pixel_format: ironrdp_egfx::pdu::PixelFormat::XRgb,
            destination_rectangle: ironrdp_pdu::geometry::ExclusiveRectangle { left: 0, top: 0, right: 16, bottom: 16 },
            bitmap_data: Vec::new(),
        })
    }

    fn v10_7() -> CapabilitySet {
        CapabilitySet::V10_7 { flags: ironrdp_egfx::pdu::CapabilitiesV107Flags::SMALL_CACHE }
    }

    #[test]
    fn avc420_takes_the_fast_conversion_once_v10_7_is_confirmed() {
        let (mut h, planes, _) = handler();
        h.on_capabilities_confirmed(&v10_7());
        assert!(!planes.load(Ordering::Relaxed), "AVC420 must use our SIMD RGBA path");
    }

    #[test]
    fn versions_that_cannot_be_reset_keep_planes() {
        let (mut h, planes, _) = handler();
        h.on_capabilities_confirmed(&CapabilitySet::V10 {
            flags: ironrdp_egfx::pdu::CapabilitiesV10Flags::SMALL_CACHE,
        });
        assert!(planes.load(Ordering::Relaxed));
    }

    #[test]
    fn avc444_switches_planes_back_on_and_resets_the_stream_once() {
        let (mut h, planes, reset) = handler();
        h.on_capabilities_confirmed(&v10_7());
        h.on_unhandled_pdu(&avc444_frame());
        assert!(planes.load(Ordering::Relaxed));
        assert!(reset.swap(false, Ordering::Relaxed));
        // The reset's confirmation must not turn planes off again, nor trigger another reset.
        h.on_capabilities_confirmed(&v10_7());
        h.on_unhandled_pdu(&avc444_frame());
        assert!(planes.load(Ordering::Relaxed));
        assert!(!reset.load(Ordering::Relaxed));
    }

    #[test]
    fn graphics_time_is_attributed_to_the_codec_used() {
        use ironrdp_egfx::pdu::Codec1Type as C;
        assert_eq!(codec_bit(C::ClearCodec, false), Some(codec_bits::CLEARCODEC));
        assert_eq!(codec_bit(C::Avc420, false), Some(codec_bits::AVC420));
        // Progressive tiles surface as "uncompressed" updates; they still count as progressive.
        assert_eq!(codec_bit(C::Uncompressed, true), None);
        assert_eq!(codec_bit(C::Uncompressed, false), Some(codec_bits::OTHER));

        let (mut h, _, _) = handler();
        let pdu = ironrdp_egfx::pdu::WireToSurface2Pdu {
            surface_id: 0,
            codec_id: ironrdp_egfx::pdu::Codec2Type::RemoteFxProgressive,
            codec_context_id: 0,
            pixel_format: ironrdp_egfx::pdu::PixelFormat::XRgb,
            bitmap_data: Vec::new(),
        };
        h.on_wire_to_surface2(&pdu);
        assert_eq!(h.codecs.swap(0, Ordering::Relaxed), codec_bits::PROGRESSIVE);
    }

    /// Server → client message as it arrives on the channel (ZGFX segment, uncompressed).
    fn wire(pdu: GfxPdu) -> Vec<u8> {
        ironrdp_graphics::zgfx::wrap_uncompressed(&ironrdp_core::encode_vec(&pdu).unwrap())
    }

    #[test]
    fn recordings_replay_through_the_pipeline() {
        use ironrdp_egfx::pdu::*;
        let monitor = ironrdp_pdu::gcc::Monitor {
            left: 0,
            top: 0,
            right: 63,
            bottom: 47,
            flags: ironrdp_pdu::gcc::MonitorFlags::PRIMARY,
        };
        let msgs = [
            GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            })),
            GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 64, height: 48, monitors: vec![monitor] }),
            GfxPdu::CreateSurface(CreateSurfacePdu {
                surface_id: 1,
                width: 64,
                height: 48,
                pixel_format: PixelFormat::XRgb,
            }),
        ];
        let mut file = CAPTURE_MAGIC.to_vec();
        for m in msgs {
            let w = wire(m);
            file.extend_from_slice(&(w.len() as u32).to_le_bytes());
            file.extend_from_slice(&w);
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gfx.bin");
        std::fs::write(&path, &file).unwrap();
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let stats = replay_capture(&path, &display).unwrap();
        assert_eq!(stats.messages, 3);

        std::fs::write(&path, b"not a recording").unwrap();
        assert!(replay_capture(&path, &display).is_err());
    }

    #[test]
    fn log_gate_lets_a_burst_through_per_window() {
        let gate = LogGate::new();
        assert_eq!((0..10_000).filter(|_| gate.allow_in(1)).count() as u64, LogGate::BURST);
        assert_eq!((0..10_000).filter(|_| gate.allow_in(2)).count() as u64, LogGate::BURST);
    }

    #[test]
    fn queue_holds_a_bounded_number_of_bytes_and_blocks_the_sender_beyond_it() {
        let data = |n: usize| Job::Data(1, vec![0; n]);
        let q = Arc::new(Queue::new(1000));
        let short = Duration::from_millis(20);
        // A message larger than the whole budget is still accepted when nothing is queued.
        assert_eq!(q.push(data(5000), short), Ok(()));
        // Nothing more fits until the thread takes it: the sender waits, then gives up.
        assert_eq!(q.push(data(10), short), Err(Stalled));
        assert_eq!(q.push(Job::Data(1, Vec::new()), short), Err(Stalled), "empty messages are charged too");
        assert!(matches!(q.pop(), Some(Job::Data(1, d)) if d.len() == 5000));
        assert_eq!(q.push(data(400), short), Ok(()));
        assert_eq!(q.push(data(400), short), Ok(()));
        assert_eq!(q.push(data(400), short), Err(Stalled), "1200 bytes > 1000");
        assert_eq!(lock(&q.state).jobs.len(), 2, "a refused message is not queued");

        // A blocked sender resumes as soon as the thread makes room (TCP back-pressure, not loss).
        let q2 = q.clone();
        let sender = std::thread::spawn(move || q2.push(data(400), Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(30));
        assert!(q.pop().is_some());
        assert_eq!(sender.join().unwrap(), Ok(()));
        assert_eq!(lock(&q.state).jobs.len(), 2);

        // Closing frees everything, wakes a blocked sender, and hands out nothing more.
        let q2 = q.clone();
        let sender = std::thread::spawn(move || q2.push(data(900), Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(30));
        q.close();
        assert_eq!(sender.join().unwrap(), Ok(()));
        assert!(q.pop().is_none());
        let st = lock(&q.state);
        assert_eq!((st.jobs.len(), st.bytes), (0, 0));
    }

    #[test]
    fn a_session_has_one_live_pipeline_and_a_cap_on_threads() {
        let mut p = Pipelines::default();
        let queues: Vec<_> = (0..MAX_PIPELINE_THREADS + 2).map(|_| Arc::new(Queue::new(1))).collect();
        for (i, q) in queues.iter().enumerate() {
            // Threads never finish here (as if each were stuck in a message).
            assert_eq!(p.admit(q), i < MAX_PIPELINE_THREADS, "pipeline {i}");
            if (1..=MAX_PIPELINE_THREADS).contains(&i) {
                assert!(queues[i - 1].is_closed(), "the previous pipeline is retired");
            }
        }
        assert_eq!(p.threads, MAX_PIPELINE_THREADS);
        assert!(p.current.is_none(), "a refused channel still retires the live one");
        // Once a retired thread ends there is room again.
        p.finished(&queues[0]);
        let next = Arc::new(Queue::new(1));
        assert!(p.admit(&next));
        assert!(!next.is_closed());
        p.finished(&next);
        assert!(p.current.is_none());
    }

    fn test_shared() -> (GfxShared, mpsc::UnboundedReceiver<Command>) {
        let (replies, rx) = mpsc::unbounded_channel();
        let shared = GfxShared {
            frame: Arc::new(SharedFrame::default()),
            waker: Arc::new(|| {}),
            replies,
            active: Arc::default(),
        };
        (shared, rx)
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn opening_channel_after_channel_never_accumulates_threads() {
        let (shared, mut rx) = test_shared();
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        // What a hostile server does: Create Requests under ever new channel ids, never closed.
        let mut open = Vec::new();
        for id in 0..200u32 {
            let mut fwd = GfxForwarder::spawn(&display, shared.clone());
            // Refused ones answer "no listener" (start fails); admitted ones retire the last.
            let _ = fwd.start(id);
            open.push(fwd);
            assert!(lock(&shared.frame.gfx).threads <= MAX_PIPELINE_THREADS);
        }
        // All but (at most) the newest end by themselves, although every forwarder is still held.
        wait_for("retired graphics threads to end", || lock(&shared.frame.gfx).threads <= 1);
        // A fresh channel is then accepted and works: it advertises capabilities.
        while rx.try_recv().is_ok() {}
        let mut fwd = GfxForwarder::spawn(&display, shared.clone());
        fwd.start(999).expect("a new channel is accepted once the old threads are gone");
        assert!(matches!(rx.blocking_recv(), Some(Command::GfxReply(_))));
        drop(fwd);
        drop(open);
        wait_for("the last graphics thread to end", || lock(&shared.frame.gfx).threads == 0);
        assert!(lock(&shared.frame.gfx).current.is_none());
    }

    #[test]
    fn a_reset_to_an_unsupported_desktop_size_ends_the_session_without_allocating() {
        use ironrdp_egfx::pdu::*;
        let (shared, mut rx) = test_shared();
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let mut fwd = GfxForwarder::spawn(&display, shared.clone());
        fwd.start(7).unwrap();
        assert!(rx.blocking_recv().is_some());
        // The pipeline's own limits (32766 per side, 256 MiB) are the shared frame's, so the
        // frame is told to refuse the size the way it refuses one beyond them.
        shared.frame.refuse_resets.store(true, Ordering::Relaxed);
        let reset = || wire(GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 64, height: 48, monitors: Vec::new() }));
        fwd.process(
            7,
            &wire(GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            }))),
        )
        .unwrap();
        fwd.process(7, &reset()).unwrap();
        // The graphics thread refuses the size and ends the session itself: the server may send
        // nothing more (it waits for a frame acknowledgement that never comes).
        let mut failed = None;
        wait_for("the graphics thread to end the session", || {
            while let Ok(cmd) = rx.try_recv() {
                if let Command::GfxFailed(message) = cmd {
                    failed = Some(message);
                }
            }
            failed.is_some()
        });
        assert_eq!(failed, Some(FRAME_SIZE_MESSAGE));
        // Should the server send more before the session ends, the channel refuses it.
        let mut error = None;
        wait_for("the refused size to be reported", || {
            error = fwd.process(7, &reset()).err();
            error.is_some()
        });
        assert!(error.unwrap().to_string().contains(FRAME_SIZE_MESSAGE));
        let f = shared.frame.lock();
        assert_eq!((f.width, f.height, f.data.len(), f.generation), (0, 0, 0, 0));
        drop(f);
        assert!(!shared.active.load(Ordering::Relaxed), "the pipeline never took over the frame");
        wait_for("the graphics thread to end", || lock(&shared.frame.gfx).threads == 0);
    }

    #[test]
    fn a_reset_to_a_wide_multi_monitor_desktop_is_accepted() {
        use ironrdp_egfx::pdu::*;
        let (shared, mut rx) = test_shared();
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let mut fwd = GfxForwarder::spawn(&display, shared.clone());
        fwd.start(7).unwrap();
        assert!(rx.blocking_recv().is_some());
        fwd.process(
            7,
            &wire(GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            }))),
        )
        .unwrap();
        // Three 4K monitors side by side: wider than one monitor's 8192.
        fwd.process(
            7,
            &wire(GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 11_520, height: 2160, monitors: Vec::new() })),
        )
        .unwrap();
        wait_for("the pipeline to take over the frame", || shared.active.load(Ordering::Relaxed));
        let f = shared.frame.lock();
        assert_eq!((f.width, f.height, f.data.len()), (11_520, 2160, 11_520 * 2160 * 4));
        drop(f);
        while let Ok(cmd) = rx.try_recv() {
            assert!(!matches!(cmd, Command::GfxFailed(_)), "the session must go on");
        }
    }

    /// One server message that sets up a 64×48 output and paints a frame (acknowledged).
    fn painted_frame() -> Vec<u8> {
        use ironrdp_egfx::pdu::*;
        use ironrdp_pdu::geometry::ExclusiveRectangle;
        let ts = Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 };
        let monitor = ironrdp_pdu::gcc::Monitor {
            left: 0,
            top: 0,
            right: 63,
            bottom: 47,
            flags: ironrdp_pdu::gcc::MonitorFlags::PRIMARY,
        };
        let mut raw = Vec::new();
        for pdu in [
            GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            })),
            GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 64, height: 48, monitors: vec![monitor] }),
            GfxPdu::CreateSurface(CreateSurfacePdu {
                surface_id: 1,
                width: 64,
                height: 48,
                pixel_format: PixelFormat::XRgb,
            }),
            GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
            GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id: 1 }),
            GfxPdu::SolidFill(SolidFillPdu {
                surface_id: 1,
                fill_pixel: Color { b: 0, g: 0, r: 255, xa: 255 },
                rectangles: vec![ExclusiveRectangle { left: 0, top: 0, right: 16, bottom: 8 }],
            }),
            GfxPdu::EndFrame(EndFramePdu { frame_id: 1 }),
        ] {
            raw.extend_from_slice(&ironrdp_core::encode_vec(&pdu).unwrap());
        }
        ironrdp_graphics::zgfx::wrap_uncompressed(&raw)
    }

    #[test]
    fn a_pipeline_closed_mid_message_discards_that_message() {
        let (shared, mut rx) = test_shared();
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let mut fwd = GfxForwarder::spawn(&display, shared.clone());
        fwd.start(7).unwrap();
        assert!(matches!(rx.blocking_recv(), Some(Command::GfxReply(_))), "capabilities advertised");
        let queue = fwd.queue.clone().unwrap();
        {
            // Keeps the thread from publishing until the channel has closed under it (as when
            // Windows reopens the channel at logon while a message is being decoded).
            let _pipelines = lock(&shared.frame.gfx);
            fwd.process(7, &painted_frame()).unwrap();
            wait_for("the graphics thread to take the message", || lock(&queue.state).jobs.is_empty());
            fwd.close(7);
        }
        wait_for("the graphics thread to end", || lock(&shared.frame.gfx).threads == 0);
        let f = shared.frame.lock();
        assert_eq!((f.width, f.height, f.data.len()), (0, 0, 0), "a closed pipeline must not resize the frame");
        assert!(f.dirty.is_empty());
        drop(f);
        assert!(!shared.active.load(Ordering::Relaxed));
        assert!(rx.try_recv().is_err(), "a closed pipeline must not acknowledge or reply");
    }

    #[test]
    fn graphics_thread_paints_the_shared_frame_and_acknowledges() {
        use ironrdp_egfx::pdu::*;
        use ironrdp_pdu::geometry::ExclusiveRectangle;

        let frame = Arc::new(SharedFrame::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let woken = Arc::new(AtomicBool::new(false));
        let w = woken.clone();
        let shared = GfxShared {
            frame: frame.clone(),
            waker: Arc::new(move || w.store(true, Ordering::Relaxed)),
            replies: tx,
            active: Arc::default(),
        };
        let display = bastion_core::profile::DisplaySettings { h264: false, ..Default::default() };
        let mut fwd = GfxForwarder::spawn(&display, shared.clone());

        // Start: the capabilities advertisement comes back as a reply for the session loop.
        assert!(fwd.start(7).unwrap().is_empty(), "replies go through the session loop");
        let first = rx.blocking_recv().expect("capabilities reply");
        assert!(matches!(first, Command::GfxReply(_)));

        let red = Color { b: 0, g: 0, r: 255, xa: 255 };
        let rect = ExclusiveRectangle { left: 0, top: 0, right: 16, bottom: 8 };
        let ts = Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 };
        let monitor = ironrdp_pdu::gcc::Monitor {
            left: 0,
            top: 0,
            right: 63,
            bottom: 47,
            flags: ironrdp_pdu::gcc::MonitorFlags::PRIMARY,
        };
        for pdu in [
            GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            })),
            GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 64, height: 48, monitors: vec![monitor] }),
            GfxPdu::CreateSurface(CreateSurfacePdu {
                surface_id: 1,
                width: 64,
                height: 48,
                pixel_format: PixelFormat::XRgb,
            }),
            GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
            GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id: 1 }),
            GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: red, rectangles: vec![rect] }),
            GfxPdu::EndFrame(EndFramePdu { frame_id: 1 }),
        ] {
            fwd.process(7, &wire(pdu)).unwrap();
        }

        // The frame acknowledgement comes back once the frame is decoded…
        let ack = rx.blocking_recv().expect("frame acknowledgement");
        assert!(matches!(ack, Command::GfxReply(_)));
        // …and the pixels are already in the shared frame, at the size ResetGraphics announced.
        let f = frame.lock();
        assert_eq!((f.width, f.height), (64, 48));
        let px = &f.data[(4 * 64 + 4) * 4..][..4];
        assert_eq!(px[..3], [255, 0, 0], "red fill composited as RGBA");
        let outside = &f.data[(40 * 64 + 40) * 4..][..3];
        assert_ne!(outside, [255, 0, 0]);
        assert!(f.dirty.iter().any(|r| r.x == 0 && r.y == 0 && r.w >= 16 && r.h >= 8), "{:?}", f.dirty);
        drop(f);
        assert!(shared.active.load(Ordering::Relaxed));
        assert!(woken.load(Ordering::Relaxed));
        drop(fwd); // ends the thread
    }
}
