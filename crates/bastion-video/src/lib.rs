//! H.264 decoding for the RDP graphics pipeline (MS-RDPEGFX AVC420/AVC444) via FFmpeg.
//!
//! Hardware decode is tried in order NVDEC (CUDA) → VAAPI, falling back to FFmpeg's software
//! decoder (slice-threaded). If the hardware path fails mid-stream, the decoder transparently
//! re-opens in software mode and waits for the next IDR frame.
//!
//! The decoder is configured for low delay: every input access unit yields its own picture
//! (no reordering), which AVC444 relies on.

#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ptr;

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
}

impl Default for DecoderOptions {
    fn default() -> Self {
        Self { prefer_hardware: true, yuv420_planes: false }
    }
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
    fn open(accel: Accel) -> DecoderResult<Self> {
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
    opts: DecoderOptions,
    frame: Frame,
    sw_frame: Frame,
    input: Vec<u8>,
    hw_failures: u32,
}

// SAFETY: all FFmpeg objects are exclusively owned and only used through `&mut self`.
unsafe impl Send for FfmpegH264Decoder {}

impl FfmpegH264Decoder {
    pub fn new(opts: DecoderOptions) -> DecoderResult<Self> {
        let ctx = Self::open_best(opts.prefer_hardware)?;
        info!(accel = ctx.accel.name(), "H.264 decoder ready");
        Ok(Self { ctx, opts, frame: Frame::new(), sw_frame: Frame::new(), input: Vec::new(), hw_failures: 0 })
    }

    pub fn accel(&self) -> Accel {
        self.ctx.accel
    }

    fn open_best(prefer_hw: bool) -> DecoderResult<Context> {
        if prefer_hw && std::env::var_os("BASTION_NO_HWDEC").is_none() {
            for accel in [Accel::Cuda, Accel::Vaapi] {
                match Context::open(accel) {
                    Ok(c) => return Ok(c),
                    Err(e) => debug!(accel = accel.name(), error = %e, "Hardware decoder unavailable"),
                }
            }
        }
        Context::open(Accel::Software)
    }

    fn fall_back_to_software(&mut self) -> DecoderResult<()> {
        warn!(from = self.ctx.accel.name(), "Hardware H.264 decode failed; switching to software");
        self.ctx = Context::open(Accel::Software)?;
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
        self.input.resize(payload_len + ffi::AV_INPUT_BUFFER_PADDING_SIZE as usize, 0);

        let r = self.send_and_receive(payload_len);
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

unsafe fn planes<'a>(f: *const ffi::AVFrame) -> DecoderResult<Planes<'a>> {
    unsafe {
        let w = u32::try_from((*f).width).map_err(|_| DecoderError::msg("bad frame width"))?;
        let h = u32::try_from((*f).height).map_err(|_| DecoderError::msg("bad frame height"))?;
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
        to_rgba(&unsafe { planes(f)? })
    }

    fn decode_yuv420(&mut self, data: &[u8]) -> DecoderResult<Yuv420Frame> {
        let f = self.decode_raw(data)?;
        to_yuv420(&unsafe { planes(f)? })
    }

    fn supports_yuv420(&self) -> bool {
        self.opts.yuv420_planes
    }

    fn reset(&mut self) {
        unsafe { ffi::avcodec_flush_buffers(self.ctx.ctx) };
    }
}
