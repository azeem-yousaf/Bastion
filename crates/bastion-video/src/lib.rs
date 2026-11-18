//! H.264 decoding for the RDP graphics pipeline (MS-RDPEGFX AVC420/AVC444) via FFmpeg.
//!
//! Hardware decode is tried in order NVDEC (CUDA) → VAAPI, falling back to FFmpeg's software
//! decoder (slice-threaded). If the hardware path fails mid-stream, the decoder transparently
//! re-opens in software mode and waits for the next IDR frame.
//!
//! In adaptive mode (what sessions use) it starts in *software*: measured on a real session,
//! remote-desktop H.264 (2560×1440, mostly small changes) took 1.5 ms per frame in software on
//! a 14-core CPU against 9 ms for NVDEC plus 5 ms to copy each frame back to system memory. If
//! software decoding can't keep up, it switches to hardware at the next IDR frame and asks for
//! one through the keyframe request flag.
//!
//! The decoder is configured for low delay: every input access unit yields its own picture
//! (no reordering), which AVC444 relies on.
//!
//! The picture size is whatever the stream's SPS says, i.e. chosen by the server, so it is
//! capped like a desktop ([`MAX_DESKTOP_SIDE`] per side, [`MAX_DESKTOP_PIXELS`] in area, both
//! rounded up to whole macroblocks): FFmpeg refuses larger streams before allocating pictures
//! for them (`max_pixels`), and nothing larger is ever converted.

#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use ffmpeg_next::ffi;
use ironrdp_egfx::decode::{DecodedFrame, DecoderError, DecoderResult, H264Decoder, Yuv420Frame};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accel {
    Software,
    Cuda,
    Vaapi,
}

impl Accel {
    pub fn name(self) -> &'static str {
        match self {
            Accel::Software => "software",
            Accel::Cuda => "NVDEC (CUDA)",
            Accel::Vaapi => "VAAPI",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DecoderOptions {
    pub prefer_hardware: bool,
    /// Return YUV planes to the pipeline (enables AVC444). Costs a slower RGBA conversion
    /// inside IronRDP for AVC420 streams, so it is off unless AVC444 quality is wanted.
    pub yuv420_planes: bool,
    /// Start in software and move to hardware (if `prefer_hardware`) only when software
    /// decoding is too slow. Without it, hardware is used from the start when preferred.
    pub adaptive: bool,
}

impl Default for DecoderOptions {
    fn default() -> Self {
        Self { prefer_hardware: true, yuv420_planes: false, adaptive: false }
    }
}

/// Largest remote desktop (and graphics surface) side, in pixels: the limit of RDP's virtual
/// desktop (monitor layouts span at most 32766 pixels, MS-RDPEDISP 2.2.2.2.1). A multi-monitor
/// desktop is the bounding box of all monitors, so it can be much wider than one monitor's 8192.
pub const MAX_DESKTOP_SIDE: u32 = 32_766;

/// Largest remote desktop area, in pixels: that of 8192 × 8192, i.e. 256 MiB as RGBA whatever
/// its shape. Three 4K monitors side by side (11520 × 2160) are 25 million.
pub const MAX_DESKTOP_PIXELS: u64 = 8192 * 8192;

/// Whether a desktop (or frame) of `width` × `height` chosen by the remote computer is within
/// [`MAX_DESKTOP_SIDE`] and [`MAX_DESKTOP_PIXELS`]. This is the one limit every part of Bastion
/// applies to server-chosen sizes.
pub fn desktop_size_ok(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_DESKTOP_SIDE
        && height <= MAX_DESKTOP_SIDE
        && u64::from(width) * u64::from(height) <= MAX_DESKTOP_PIXELS
}

/// Largest H.264 picture side decoded: a desktop side rounded up to whole macroblocks (a
/// legitimate stream is the size of the surface it paints, rounded up to multiples of 16).
pub const MAX_PICTURE_SIDE: u32 = MAX_DESKTOP_SIDE.next_multiple_of(16);

/// The largest area a picture of `width` × `height` may have: the desktop limit plus what
/// rounding a surface up to whole macroblocks adds (less than 16 pixels per row and column).
fn max_picture_pixels(width: u32, height: u32) -> u64 {
    MAX_DESKTOP_PIXELS + 16 * (u64::from(width) + u64::from(height))
}

/// Refuses decoded pictures larger than `max_side` per side or larger in area than any
/// desktop, before anything is allocated or converted for them.
fn check_picture_size(width: u32, height: u32, max_side: u32) -> DecoderResult<()> {
    if width > max_side || height > max_side || u64::from(width) * u64::from(height) > max_picture_pixels(width, height)
    {
        return Err(DecoderError::msg(format!(
            "H.264 picture of {width}x{height} exceeds the size limit ({max_side} per side)"
        )));
    }
    Ok(())
}

/// Average software decode time (ms per frame) above which adaptive mode moves to hardware.
pub const ADAPTIVE_SWITCH_MS: f64 = 16.0;
/// Frames observed before adaptive mode may decide.
const ADAPTIVE_MIN_FRAMES: u32 = 30;

/// Adaptive-mode bookkeeping (see the module docs).
#[derive(Debug, Default)]
struct Adaptive {
    /// Exponential moving average of software decode time, in ms.
    avg_ms: f64,
    frames: u32,
    /// Waiting for an IDR frame to switch to hardware.
    switch_pending: bool,
    /// Set to ask the server for a keyframe.
    keyframe_request: Option<Arc<AtomicBool>>,
}

impl Adaptive {
    /// Records one software decode; returns true when it is time to switch.
    fn observe(&mut self, ms: f64) -> bool {
        self.frames += 1;
        self.avg_ms = if self.frames == 1 { ms } else { self.avg_ms * 0.9 + ms * 0.1 };
        !self.switch_pending && self.frames >= ADAPTIVE_MIN_FRAMES && self.avg_ms > ADAPTIVE_SWITCH_MS
    }
}

/// Whether an Annex B access unit contains an IDR slice (NAL unit type 5).
pub fn contains_idr(annex_b: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < annex_b.len() {
        if annex_b[i] == 0 && annex_b[i + 1] == 0 && annex_b[i + 2] == 1 {
            if annex_b[i + 3] & 0x1F == 5 {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Creates the best available decoder, or `None` if FFmpeg has no H.264 decoder at all
/// (the pipeline then simply doesn't advertise AVC and the server uses RemoteFX).
pub fn create_decoder(opts: DecoderOptions) -> Option<Box<dyn H264Decoder>> {
    match FfmpegH264Decoder::new(opts) {
        Ok(d) => Some(Box::new(d)),
        Err(e) => {
            warn!(error = %e, "H.264 decoding unavailable");
            None
        }
    }
}

struct Context {
    ctx: *mut ffi::AVCodecContext,
    accel: Accel,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::avcodec_free_context(&mut self.ctx) };
    }
}

/// Picks the hardware pixel format if offered, else the first software format.
unsafe extern "C" fn get_format(ctx: *mut ffi::AVCodecContext, fmts: *const ffi::AVPixelFormat) -> ffi::AVPixelFormat {
    unsafe {
        let wanted = (*ctx).opaque as isize as i32;
        let mut p = fmts;
        let mut first_sw = ffi::AVPixelFormat::AV_PIX_FMT_NONE;
        while *p != ffi::AVPixelFormat::AV_PIX_FMT_NONE {
            if *p as i32 == wanted {
                return *p;
            }
            if first_sw == ffi::AVPixelFormat::AV_PIX_FMT_NONE
                && *p != ffi::AVPixelFormat::AV_PIX_FMT_CUDA
                && *p != ffi::AVPixelFormat::AV_PIX_FMT_VAAPI
            {
                first_sw = *p;
            }
            p = p.add(1);
        }
        first_sw
    }
}

fn err(ctx: &str, code: c_int) -> DecoderError {
    DecoderError::new(ctx.to_owned(), ffmpeg_next::Error::from(code))
}

impl Context {
    /// Limits the coded picture area FFmpeg accepts (checked when a stream's SPS is activated,
    /// before it allocates pictures): `max_dim` × `max_dim`, and never more than the largest
    /// desktop allows. Each side is checked again before conversion ([`check_picture_size`]).
    fn limit_picture_size(&mut self, max_dim: u32) {
        let square = u64::from(max_dim) * u64::from(max_dim);
        let area = square.min(max_picture_pixels(MAX_PICTURE_SIDE, MAX_PICTURE_SIDE));
        unsafe { (*self.ctx).max_pixels = i64::try_from(area).unwrap_or(i64::MAX) };
    }

    fn open(accel: Accel, max_dim: u32) -> DecoderResult<Self> {
        unsafe {
            let codec = ffi::avcodec_find_decoder(ffi::AVCodecID::AV_CODEC_ID_H264);
            if codec.is_null() {
                return Err(DecoderError::msg("FFmpeg has no H.264 decoder"));
            }
            let ctx = ffi::avcodec_alloc_context3(codec);
            if ctx.is_null() {
                return Err(DecoderError::msg("avcodec_alloc_context3 failed"));
            }
            let mut this = Self { ctx, accel };
            this.limit_picture_size(max_dim);
            (*ctx).flags |= ffi::AV_CODEC_FLAG_LOW_DELAY as c_int;
            (*ctx).flags2 |= ffi::AV_CODEC_FLAG2_SHOW_ALL as c_int;
            match accel {
                Accel::Software => {
                    // Slice threading adds no latency (frame threading would delay output).
                    (*ctx).thread_type = ffi::FF_THREAD_SLICE as c_int;
                    (*ctx).thread_count = 0;
                }
                Accel::Cuda | Accel::Vaapi => {
                    let (dev_type, pix) = if accel == Accel::Cuda {
                        (ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_CUDA, ffi::AVPixelFormat::AV_PIX_FMT_CUDA)
                    } else {
                        (ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI, ffi::AVPixelFormat::AV_PIX_FMT_VAAPI)
                    };
                    let mut dev: *mut ffi::AVBufferRef = ptr::null_mut();
                    let r = ffi::av_hwdevice_ctx_create(&mut dev, dev_type, ptr::null(), ptr::null_mut(), 0);
                    if r < 0 {
                        return Err(err("create hardware device", r));
                    }
                    (*ctx).hw_device_ctx = dev; // ownership moves to the codec context
                    (*ctx).opaque = pix as i32 as isize as *mut _;
                    (*ctx).get_format = Some(get_format);
                    (*ctx).thread_count = 1;
                }
            }
            let r = ffi::avcodec_open2(ctx, codec, ptr::null_mut());
            if r < 0 {
                return Err(err("avcodec_open2", r));
            }
            this.accel = accel;
            Ok(this)
        }
    }
}

struct Frame(*mut ffi::AVFrame);

impl Frame {
    fn new() -> Self {
        Self(unsafe { ffi::av_frame_alloc() })
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        unsafe { ffi::av_frame_free(&mut self.0) };
    }
}

pub struct FfmpegH264Decoder {
    ctx: Context,
    frame: Frame,
    sw_frame: Frame,
    input: Vec<u8>,
    hw_failures: u32,
    /// `Some` while adaptive mode may still move to hardware.
    adaptive: Option<Adaptive>,
    /// What `supports_yuv420` answers; see [`FfmpegH264Decoder::yuv420_switch`].
    planes: Arc<AtomicBool>,
    /// Largest picture edge accepted (see [`MAX_PICTURE_SIDE`]).
    max_dim: u32,
}

// SAFETY: all FFmpeg objects are exclusively owned and only used through `&mut self`.
unsafe impl Send for FfmpegH264Decoder {}

impl FfmpegH264Decoder {
    pub fn new(opts: DecoderOptions) -> DecoderResult<Self> {
        let hw_allowed = opts.prefer_hardware && std::env::var_os("BASTION_NO_HWDEC").is_none();
        let adaptive = (opts.adaptive && hw_allowed).then(Adaptive::default);
        let ctx = Self::open_best(opts.prefer_hardware && adaptive.is_none(), MAX_PICTURE_SIDE)?;
        // A server can make the session open a decoder per graphics channel it creates, so
        // only the first few and then every 64th are logged.
        static OPENED: AtomicU64 = AtomicU64::new(0);
        let opened = OPENED.fetch_add(1, Ordering::Relaxed) + 1;
        if opened <= 8 || opened.is_multiple_of(64) {
            info!(accel = ctx.accel.name(), opened, "H.264 decoder ready");
        }
        Ok(Self {
            ctx,
            frame: Frame::new(),
            sw_frame: Frame::new(),
            input: Vec::new(),
            hw_failures: 0,
            adaptive,
            planes: Arc::new(AtomicBool::new(opts.yuv420_planes)),
            max_dim: MAX_PICTURE_SIDE,
        })
    }

    /// Lowers the largest picture edge accepted (never above [`MAX_PICTURE_SIDE`]), e.g. to the
    /// size of the desktop being shown. Streams announcing a larger picture then fail to decode.
    pub fn set_max_dimension(&mut self, max_dim: u32) {
        self.max_dim = max_dim.clamp(16, MAX_PICTURE_SIDE);
        self.ctx.limit_picture_size(self.max_dim);
    }

    /// Flag the decoder sets to ask the server for a keyframe (adaptive mode, before switching
    /// to hardware). The session turns it into a graphics stream reset.
    pub fn set_keyframe_request(&mut self, flag: Arc<AtomicBool>) {
        if let Some(a) = self.adaptive.as_mut() {
            a.keyframe_request = Some(flag);
        }
    }

    /// Adaptive mode: move to hardware decoding at the next IDR frame, and ask the server for
    /// one. Does nothing outside adaptive mode or once switched.
    pub fn switch_to_hardware_at_next_keyframe(&mut self) {
        if let Some(a) = self.adaptive.as_mut() {
            a.switch_pending = true;
            if let Some(flag) = &a.keyframe_request {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Opens a hardware decoder, if any works.
    fn open_hardware(max_dim: u32) -> Option<Context> {
        [Accel::Cuda, Accel::Vaapi].into_iter().find_map(|accel| {
            Context::open(accel, max_dim)
                .map_err(|e| debug!(accel = accel.name(), error = %e, "Hardware decoder unavailable"))
                .ok()
        })
    }

    /// Switch for returning YUV planes, which can change after creation.
    ///
    /// IronRDP asks `supports_yuv420` both when choosing which pipeline versions to advertise
    /// (all modern ones imply AVC444, which needs planes) and for every AVC420 frame (planes are
    /// then converted by IronRDP one pixel at a time — 25–80 ms per frame, versus ~2 ms for our
    /// SIMD conversion). The session turns planes on for advertising and off once it knows the
    /// server streams AVC420.
    pub fn yuv420_switch(&self) -> Arc<AtomicBool> {
        self.planes.clone()
    }

    pub fn accel(&self) -> Accel {
        self.ctx.accel
    }

    fn open_best(prefer_hw: bool, max_dim: u32) -> DecoderResult<Context> {
        if prefer_hw && std::env::var_os("BASTION_NO_HWDEC").is_none() {
            for accel in [Accel::Cuda, Accel::Vaapi] {
                match Context::open(accel, max_dim) {
                    Ok(c) => return Ok(c),
                    Err(e) => debug!(accel = accel.name(), error = %e, "Hardware decoder unavailable"),
                }
            }
        }
        Context::open(Accel::Software, max_dim)
    }

    fn fall_back_to_software(&mut self) -> DecoderResult<()> {
        warn!(from = self.ctx.accel.name(), "Hardware H.264 decode failed; switching to software");
        bastion_metrics::VIDEO_HW_FALLBACKS.incr();
        self.ctx = Context::open(Accel::Software, self.max_dim)?;
        Ok(())
    }

    /// Sends one access unit and returns a pointer to the decoded (system-memory) frame.
    fn decode_raw(&mut self, data: &[u8]) -> DecoderResult<*const ffi::AVFrame> {
        // FFmpeg reads Annex B; RDP may send AVC (length-prefixed) NAL units.
        self.input.clear();
        if ironrdp_egfx::pdu::is_avc_format(data) {
            ironrdp_egfx::pdu::avc_to_annex_b_into(data, &mut self.input);
        } else {
            self.input.extend_from_slice(data);
        }
        let payload_len = self.input.len();
        if self.adaptive.as_ref().is_some_and(|a| a.switch_pending) && contains_idr(&self.input) {
            // A keyframe: the hardware decoder can start here without artefacts.
            match Self::open_hardware(self.max_dim) {
                Some(ctx) => {
                    info!(accel = ctx.accel.name(), "Switched H.264 decoding to hardware");
                    self.ctx = ctx;
                }
                None => warn!("Software H.264 decoding is slow, but no hardware decoder is available"),
            }
            self.adaptive = None;
        }
        self.input.resize(payload_len + ffi::AV_INPUT_BUFFER_PADDING_SIZE as usize, 0);

        let started = Instant::now();
        let r = bastion_metrics::VIDEO_DECODE.time(|| self.send_and_receive(payload_len));
        if r.is_ok()
            && let Some(a) = self.adaptive.as_mut()
            && a.observe(started.elapsed().as_secs_f64() * 1e3)
        {
            info!(
                avg_ms = format!("{:.1}", a.avg_ms),
                "Software H.264 decoding can't keep up; switching to hardware at the next keyframe"
            );
            self.switch_to_hardware_at_next_keyframe();
        }
        if r.is_ok() {
            bastion_metrics::VIDEO_FRAMES.incr();
        }
        match r {
            Err(e) if self.ctx.accel != Accel::Software => {
                self.hw_failures += 1;
                if self.hw_failures >= 3 {
                    self.fall_back_to_software()?;
                }
                Err(e)
            }
            other => {
                if other.is_ok() {
                    self.hw_failures = 0;
                }
                other
            }
        }
    }

    fn send_and_receive(&mut self, len: usize) -> DecoderResult<*const ffi::AVFrame> {
        unsafe {
            let mut pkt: ffi::AVPacket = std::mem::zeroed();
            pkt.data = self.input.as_mut_ptr();
            pkt.size = c_int::try_from(len).map_err(|_| DecoderError::msg("H.264 access unit too large"))?;
            let r = ffi::avcodec_send_packet(self.ctx.ctx, &pkt);
            if r < 0 {
                return Err(err("avcodec_send_packet", r));
            }
            let r = ffi::avcodec_receive_frame(self.ctx.ctx, self.frame.0);
            if r < 0 {
                return Err(err("avcodec_receive_frame (no picture for access unit)", r));
            }
            // Drain anything else so the next call returns *its* picture (AVC444 pairing).
            loop {
                let tmp = Frame::new();
                if ffi::avcodec_receive_frame(self.ctx.ctx, tmp.0) < 0 {
                    break;
                }
                ffi::av_frame_unref(self.frame.0);
                ffi::av_frame_move_ref(self.frame.0, tmp.0);
            }
            let f = self.frame.0;
            let fmt = (*f).format;
            if fmt == ffi::AVPixelFormat::AV_PIX_FMT_CUDA as c_int
                || fmt == ffi::AVPixelFormat::AV_PIX_FMT_VAAPI as c_int
            {
                ffi::av_frame_unref(self.sw_frame.0);
                let r = ffi::av_hwframe_transfer_data(self.sw_frame.0, f, 0);
                if r < 0 {
                    return Err(err("download hardware frame", r));
                }
                return Ok(self.sw_frame.0);
            }
            Ok(f)
        }
    }
}

/// View of a decoded frame's planes.
struct Planes<'a> {
    width: u32,
    height: u32,
    y: &'a [u8],
    y_stride: usize,
    kind: PlanesKind<'a>,
}

enum PlanesKind<'a> {
    I420 { u: &'a [u8], v: &'a [u8], stride: usize },
    Nv12 { uv: &'a [u8], stride: usize },
}

unsafe fn planes<'a>(f: *const ffi::AVFrame, max_dim: u32) -> DecoderResult<Planes<'a>> {
    unsafe {
        let w = u32::try_from((*f).width).map_err(|_| DecoderError::msg("bad frame width"))?;
        let h = u32::try_from((*f).height).map_err(|_| DecoderError::msg("bad frame height"))?;
        // `max_pixels` bounds the area FFmpeg decodes; this bounds each side (a 65536×16
        // picture has an acceptable area) before any plane is copied or converted.
        check_picture_size(w, h, max_dim)?;
        let ch = h.div_ceil(2) as usize;
        let ls = |i: usize| (*f).linesize[i] as usize;
        let plane = |i: usize, rows: usize| std::slice::from_raw_parts((*f).data[i], ls(i) * rows);
        let fmt = (*f).format;
        let kind = if fmt == ffi::AVPixelFormat::AV_PIX_FMT_YUV420P as c_int
            || fmt == ffi::AVPixelFormat::AV_PIX_FMT_YUVJ420P as c_int
        {
            if ls(1) != ls(2) {
                return Err(DecoderError::msg("chroma strides differ"));
            }
            PlanesKind::I420 { u: plane(1, ch), v: plane(2, ch), stride: ls(1) }
        } else if fmt == ffi::AVPixelFormat::AV_PIX_FMT_NV12 as c_int {
            PlanesKind::Nv12 { uv: plane(1, ch), stride: ls(1) }
        } else {
            return Err(DecoderError::msg(format!("unsupported decoded pixel format {fmt}")));
        };
        Ok(Planes { width: w, height: h, y: plane(0, h as usize), y_stride: ls(0), kind })
    }
}

/// MS-RDPEGFX 3.3.8.3.1: AVC420 uses full-range BT.709.
const RANGE: yuv::YuvRange = yuv::YuvRange::Full;
const MATRIX: yuv::YuvStandardMatrix = yuv::YuvStandardMatrix::Bt709;

fn to_rgba(p: &Planes<'_>) -> DecoderResult<DecodedFrame> {
    let stride = p.width * 4;
    let mut rgba = vec![0u8; stride as usize * p.height as usize];
    let conv = |e: yuv::YuvError| DecoderError::new("YUV→RGBA conversion", e);
    match p.kind {
        PlanesKind::I420 { u, v, stride: cs } => {
            let img = yuv::YuvPlanarImage {
                y_plane: p.y,
                y_stride: p.y_stride as u32,
                u_plane: u,
                u_stride: cs as u32,
                v_plane: v,
                v_stride: cs as u32,
                width: p.width,
                height: p.height,
            };
            // Chroma is replicated over each 2×2 block on purpose. Bilinear upsampling was tried
            // and measured worse on screen content (coloured text on flat backgrounds: 35 dB
            // against 48.6 dB PSNR, visible pink/green halos): encoders average 2×2 blocks, so
            // replication reconstructs flat colours exactly.
            yuv::yuv420_to_rgba(&img, &mut rgba, stride, RANGE, MATRIX).map_err(conv)?;
        }
        PlanesKind::Nv12 { uv, stride: cs } => {
            let img = yuv::YuvBiPlanarImage {
                y_plane: p.y,
                y_stride: p.y_stride as u32,
                uv_plane: uv,
                uv_stride: cs as u32,
                width: p.width,
                height: p.height,
            };
            yuv::yuv_nv12_to_rgba(&img, &mut rgba, stride, RANGE, MATRIX, yuv::YuvConversionMode::Balanced)
                .map_err(conv)?;
        }
    }
    Ok(DecodedFrame::new(rgba, p.width, p.height))
}

fn to_yuv420(p: &Planes<'_>) -> DecoderResult<Yuv420Frame> {
    let w = u16::try_from(p.width).map_err(|_| DecoderError::msg("frame too wide"))?;
    let h = u16::try_from(p.height).map_err(|_| DecoderError::msg("frame too tall"))?;
    match p.kind {
        PlanesKind::I420 { u, v, stride } => {
            Yuv420Frame::new(w, h, p.y.to_vec(), p.y_stride, u.to_vec(), v.to_vec(), stride)
        }
        PlanesKind::Nv12 { uv, stride } => {
            let cw = usize::from(w.div_ceil(2));
            let ch = usize::from(h.div_ceil(2));
            let mut u = Vec::with_capacity(cw * ch);
            let mut v = Vec::with_capacity(cw * ch);
            for row in 0..ch {
                let line = &uv[row * stride..row * stride + cw * 2];
                for pair in line.as_chunks::<2>().0 {
                    u.push(pair[0]);
                    v.push(pair[1]);
                }
            }
            Yuv420Frame::new(w, h, p.y.to_vec(), p.y_stride, u, v, cw)
        }
    }
}

impl H264Decoder for FfmpegH264Decoder {
    fn decode(&mut self, data: &[u8]) -> DecoderResult<DecodedFrame> {
        let f = self.decode_raw(data)?;
        let max_dim = self.max_dim;
        bastion_metrics::VIDEO_CONVERT.time(|| to_rgba(&unsafe { planes(f, max_dim)? }))
    }

    fn decode_yuv420(&mut self, data: &[u8]) -> DecoderResult<Yuv420Frame> {
        let f = self.decode_raw(data)?;
        let max_dim = self.max_dim;
        bastion_metrics::VIDEO_CONVERT.time(|| to_yuv420(&unsafe { planes(f, max_dim)? }))
    }

    fn supports_yuv420(&self) -> bool {
        self.planes.load(Ordering::Relaxed)
    }

    fn reset(&mut self) {
        unsafe { ffi::avcodec_flush_buffers(self.ctx.ctx) };
    }
}

#[cfg(test)]
mod adaptive_tests {
    use super::*;

    #[test]
    fn switches_only_after_enough_slow_frames() {
        let mut a = Adaptive::default();
        for _ in 0..ADAPTIVE_MIN_FRAMES - 1 {
            assert!(!a.observe(40.0), "never before {ADAPTIVE_MIN_FRAMES} frames");
        }
        assert!(a.observe(40.0));
    }

    #[test]
    fn fast_software_decoding_stays_in_software() {
        let mut a = Adaptive::default();
        for i in 0..500 {
            // Occasional slow frames (a burst of motion) don't trigger a switch.
            let ms = if i % 50 == 0 { 30.0 } else { 2.0 };
            assert!(!a.observe(ms), "frame {i}");
        }
    }

    #[test]
    fn pictures_larger_than_any_remote_desktop_are_refused() {
        let max = MAX_PICTURE_SIDE;
        assert!(check_picture_size(8192, 8192, max).is_ok());
        assert!(check_picture_size(3840, 2160, max).is_ok());
        // Wide multi-monitor desktops: three 4K monitors side by side, 4K + 4K + 2560, and the
        // widest surface RDP allows, rounded up to whole macroblocks.
        assert!(check_picture_size(11_520, 2160, max).is_ok());
        assert!(check_picture_size(10_240, 2160, max).is_ok());
        assert!(check_picture_size(32_768, 1088, max).is_ok());
        // A surface just within the area limit, rounded up to macroblocks.
        assert!(check_picture_size(11_520, 5840, max).is_ok(), "11520x5825 surface");
        // Too wide, too tall, or too large in area (the 1 GB RGBA case from a few bytes of SPS).
        assert!(check_picture_size(32_784, 16, max).is_err());
        assert!(check_picture_size(64, 32_784, max).is_err());
        assert!(check_picture_size(16_384, 16_000, max).is_err());
        assert!(check_picture_size(8192, 8192 + 64, max).is_err());
    }

    #[test]
    fn desktop_limits_allow_wide_layouts_but_bound_memory() {
        assert!(desktop_size_ok(1920, 1080));
        assert!(desktop_size_ok(8192, 8192));
        assert!(desktop_size_ok(11_520, 2160), "three 4K monitors side by side");
        assert!(desktop_size_ok(MAX_DESKTOP_SIDE, 2048));
        assert!(desktop_size_ok(2048, MAX_DESKTOP_SIDE));
        for (w, h) in [(0, 1080), (1920, 0), (MAX_DESKTOP_SIDE + 1, 8), (8, MAX_DESKTOP_SIDE + 1), (8192, 8193)] {
            assert!(!desktop_size_ok(w, h), "{w}x{h}");
        }
        assert!(!desktop_size_ok(MAX_DESKTOP_SIDE, MAX_DESKTOP_SIDE));
        assert!(!desktop_size_ok(u32::MAX, u32::MAX));
    }

    #[test]
    fn idr_detection() {
        assert!(contains_idr(&[0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x65, 9]));
        assert!(!contains_idr(&[0, 0, 0, 1, 0x41, 1, 2, 3]), "P slice");
        assert!(!contains_idr(&[]));
    }
}
