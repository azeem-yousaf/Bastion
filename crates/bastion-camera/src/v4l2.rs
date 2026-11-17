//! Video4Linux2 camera host.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tracing::{debug, info, warn};
use v4l::buffer::Type;
use v4l::capability::Flags;
use v4l::frameinterval::FrameIntervalEnum;
use v4l::io::traits::CaptureStream as _;
use v4l::video::Capture as _;
use v4l::video::capture::Parameters;
use v4l::{Device, Format, FourCC, Fraction};

use crate::{CameraHost, CameraInfo, FrameCallback, Mode, PixelFormat, RunningCapture};

const MJPG: FourCC = FourCC { repr: *b"MJPG" };
const YUYV: FourCC = FourCC { repr: *b"YUYV" };

fn fourcc(f: PixelFormat) -> FourCC {
    match f {
        PixelFormat::Mjpeg => MJPG,
        PixelFormat::Yuyv => YUYV,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct V4l2Host;

impl CameraHost for V4l2Host {
    fn cameras(&self) -> Vec<CameraInfo> {
        let mut paths: Vec<_> = match std::fs::read_dir("/dev") {
            Ok(d) => d
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("video")))
                .collect(),
            Err(e) => {
                warn!(error = %e, "Cannot list /dev for cameras");
                return Vec::new();
            }
        };
        // /dev/video2 before /dev/video10.
        paths.sort_by_key(|p| {
            let n = p.to_string_lossy();
            (n.len(), n.into_owned())
        });
        let mut seen_bus = HashSet::new();
        let mut out = Vec::new();
        for path in paths {
            match probe(&path.to_string_lossy()) {
                Ok(Some((info, bus))) => {
                    // A camera exposes several nodes (metadata, IR sensor); keep the first usable one.
                    if seen_bus.insert(bus) {
                        debug!(id = %info.id, name = %info.name, modes = info.modes.len(), "Found camera");
                        out.push(info);
                    }
                }
                Ok(None) => {}
                Err(e) => debug!(path = %path.display(), error = %e, "Skipping video node"),
            }
        }
        out
    }

    fn start(&self, camera: &CameraInfo, mode: Mode, on_frame: FrameCallback) -> Result<Box<dyn RunningCapture>> {
        let dev = Device::with_path(&camera.id).with_context(|| format!("open {}", camera.id))?;
        let want = Format::new(mode.width, mode.height, fourcc(mode.format));
        let got = dev.set_format(&want).context("set camera format")?;
        if (got.width, got.height, got.fourcc) != (want.width, want.height, want.fourcc) {
            bail!("camera refused {}x{} {}", mode.width, mode.height, want.fourcc);
        }
        // Frame interval is seconds per frame: the inverse of the frame rate.
        if let Err(e) = dev.set_params(&Parameters::new(Fraction::new(mode.fps_den, mode.fps_num))) {
            warn!(error = %e, "Could not set camera frame rate; using the driver default");
        }
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let id = camera.id.clone();
        let frame_len = (mode.format == PixelFormat::Yuyv).then(|| (mode.width * mode.height * 2) as usize);
        let thread = std::thread::Builder::new()
            .name("bastion-camera".into())
            .spawn(move || {
                if let Err(e) = capture_loop(&dev, &s, frame_len, on_frame) {
                    warn!(camera = %id, error = %e, "Camera capture stopped");
                }
            })
            .context("spawn camera thread")?;
        info!(camera = %camera.id, ?mode, "Camera capture started");
        Ok(Box::new(V4l2Capture { stop, thread: Some(thread) }))
    }
}

fn capture_loop(dev: &Device, stop: &AtomicBool, frame_len: Option<usize>, mut on_frame: FrameCallback) -> Result<()> {
    let mut stream = v4l::io::mmap::Stream::with_buffers(dev, Type::VideoCapture, 4).context("map buffers")?;
    stream.set_timeout(Duration::from_millis(250));
    while !stop.load(Ordering::Acquire) {
        let (buf, meta) = match stream.next() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e).context("read frame"),
        };
        let data = &buf[..(meta.bytesused as usize).min(buf.len())];
        let ok = match frame_len {
            Some(len) => data.len() == len,
            // Some cameras occasionally hand over empty or truncated JPEGs; skip those.
            None => data.starts_with(&[0xFF, 0xD8]),
        };
        if ok {
            on_frame(data);
        }
    }
    Ok(())
}

struct V4l2Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RunningCapture for V4l2Capture {}

impl Drop for V4l2Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        debug!("Camera capture stopped");
    }
}

/// Returns the camera and its bus id, or `None` for nodes that aren't usable cameras.
fn probe(path: &str) -> Result<Option<(CameraInfo, String)>> {
    let dev = Device::with_path(path)?;
    let caps = dev.query_caps()?;
    if !caps.capabilities.contains(Flags::VIDEO_CAPTURE) {
        return Ok(None);
    }
    let mut modes = Vec::new();
    for desc in dev.enum_formats()? {
        let format = match desc.fourcc {
            f if f == MJPG => PixelFormat::Mjpeg,
            f if f == YUYV => PixelFormat::Yuyv,
            _ => continue,
        };
        for size in dev.enum_framesizes(desc.fourcc)? {
            for d in size.size.to_discrete() {
                for iv in dev.enum_frameintervals(desc.fourcc, d.width, d.height).unwrap_or_default() {
                    // Interval = seconds per frame, so fps = denominator / numerator.
                    let (num, den) = match iv.interval {
                        FrameIntervalEnum::Discrete(f) => (f.denominator, f.numerator),
                        FrameIntervalEnum::Stepwise(s) => (s.min.denominator, s.min.numerator),
                    };
                    if num > 0 && den > 0 {
                        modes.push(Mode { format, width: d.width, height: d.height, fps_num: num, fps_den: den });
                    }
                }
            }
        }
    }
    if modes.is_empty() {
        return Ok(None);
    }
    let name = if caps.card.trim().is_empty() { "Camera".to_owned() } else { caps.card.trim().to_owned() };
    Ok(Some((CameraInfo { id: path.to_owned(), name, modes }, caps.bus)))
}
