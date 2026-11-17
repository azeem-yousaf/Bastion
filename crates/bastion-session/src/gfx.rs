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

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
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
pub struct GfxReply(pub(crate) Vec<SvcMessage>);

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

enum Job {
    Start(u32),
    Data(u32, Vec<u8>),
    Close(u32),
}

/// Stands in for the pipeline on the dynamic channel and forwards to the graphics thread.
/// Dropping it (channel closed or session over) ends the thread.
pub(crate) struct GfxForwarder {
    jobs: std_mpsc::Sender<Job>,
}

ironrdp_core::impl_as_any!(GfxForwarder);

impl GfxForwarder {
    /// Creates the pipeline client and its thread.
    pub(crate) fn spawn(display: &bastion_core::profile::DisplaySettings, shared: GfxShared) -> Self {
        let (jobs, rx) = std_mpsc::channel();
        let codecs = Arc::new(AtomicU32::new(0));
        let reset = Arc::new(AtomicBool::new(false));
        let display = display.clone();
        let spawned = std::thread::Builder::new().name("bastion-gfx".into()).spawn(move || {
            // Created here: opening the H.264 decoder can take a moment.
            let client = gfx_client(&display, Some(reset.clone()), codecs.clone());
            run(&rx, client, &shared, &codecs, &reset);
        });
        if let Err(e) = spawned {
            warn!(error = %e, "Cannot start the graphics thread");
        }
        Self { jobs }
    }
}

impl DvcProcessor for GfxForwarder {
    fn channel_name(&self) -> &str {
        ironrdp_egfx::CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        let _ = self.jobs.send(Job::Start(channel_id));
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let _ = self.jobs.send(Job::Data(channel_id, payload.to_vec()));
        Ok(Vec::new())
    }

    fn close(&mut self, channel_id: u32) {
        let _ = self.jobs.send(Job::Close(channel_id));
    }
}

impl DvcClientProcessor for GfxForwarder {}

fn run(
    jobs: &std_mpsc::Receiver<Job>,
    mut client: GraphicsPipelineClient,
    shared: &GfxShared,
    codecs: &AtomicU32,
    reset: &AtomicBool,
) {
    let mut capture = Capture::from_env();
    while let Ok(job) = jobs.recv() {
        match job {
            Job::Start(id) => match client.start(id) {
                Ok(msgs) => reply(shared, id, msgs),
                Err(e) => warn!(error = %e, "Graphics pipeline failed to start"),
            },
            Job::Data(id, payload) => {
                if let Some(c) = capture.as_mut() {
                    c.record(&payload);
                }
                let started = Instant::now();
                let result = client.process(id, &payload);
                let took = started.elapsed();
                bastion_metrics::GFX_PROCESS.record(took);
                record_codec_time(codecs.swap(0, Ordering::Relaxed), took);
                match result {
                    Ok(msgs) => reply(shared, id, msgs),
                    Err(e) => warn!(error = %e, "Graphics pipeline error"),
                }
                if reset.swap(false, Ordering::Relaxed) {
                    match client.request_protocol_reset() {
                        Some(pdu) => {
                            info!("Requested a graphics stream reset");
                            reply(shared, id, vec![Box::new(pdu)]);
                        }
                        None => warn!("Graphics stream reset not possible"),
                    }
                }
                composite(&mut client, shared);
            }
            Job::Close(id) => {
                client.close(id);
                break;
            }
        }
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
                warn!(path = %path.display(), "Recording the graphics channel (contains screen contents)");
                let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
                std::io::Write::write_all(&mut out, CAPTURE_MAGIC).ok()?;
                Some(Self { out })
            }
            Err(e) => {
                warn!(error = %e, "Cannot record the graphics channel");
                None
            }
        }
    }

    fn record(&mut self, payload: &[u8]) {
        use std::io::Write as _;
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX).to_le_bytes();
        if self.out.write_all(&len).and_then(|()| self.out.write_all(payload)).is_err() {
            warn!("Graphics recording stopped (write failed)");
        }
    }
}

/// Totals from [`replay_capture`].
#[derive(Debug)]
pub struct ReplayStats {
    pub messages: usize,
    pub bytes: usize,
    /// Wall-clock time spent in the pipeline and compositing (excludes reading the file).
    pub busy: Duration,
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
    for msg in &messages {
        bytes += msg.len();
        let started = Instant::now();
        let result = client.process(1, msg);
        let took = started.elapsed();
        bastion_metrics::GFX_PROCESS.record(took);
        record_codec_time(codecs.swap(0, Ordering::Relaxed), took);
        if let Err(e) = result {
            warn!(error = %e, "Graphics pipeline error during replay");
        }
        let _ = reset.swap(false, Ordering::Relaxed);
        composite(&mut client, &shared);
        busy += started.elapsed();
        // The renderer would take the dirty list; keep it from growing across the replay.
        shared.frame.lock().dirty.clear();
    }
    Ok(ReplayStats { messages: messages.len(), bytes, busy })
}

fn reply(shared: &GfxShared, channel_id: u32, msgs: Vec<DvcMessage>) {
    if msgs.is_empty() {
        return;
    }
    match ironrdp_dvc::encode_dvc_messages(channel_id, msgs, ironrdp_svc::ChannelFlags::empty()) {
        Ok(svc) => {
            let _ = shared.replies.send(Command::GfxReply(GfxReply(svc)));
        }
        Err(e) => warn!(error = %e, "Cannot encode graphics pipeline reply"),
    }
}

/// Copies what the pipeline finished since the last call into the shared framebuffer.
fn composite(client: &mut GraphicsPipelineClient, shared: &GfxShared) {
    let reset = client.take_output_reset();
    if let Some((w, h)) = reset {
        shared.frame.reset(u32::from(w), u32::from(h));
        shared.active.store(true, Ordering::Release);
    }
    // RemoteApp windows are not used.
    let _ = client.drain_window_updates();
    let output = client.drain_output();
    if output.is_empty() && reset.is_none() {
        return;
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
        })
        .map_err(|e| warn!(error = %e, "H.264 decoding unavailable"))
        .ok()
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
        info!(?caps, "Graphics pipeline negotiated");
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
        info!(width, height, "Graphics output reset");
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
