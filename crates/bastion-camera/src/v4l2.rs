//! Video4Linux2 camera host.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tracing::{debug, warn};
use v4l::buffer::Type;
use v4l::capability::Flags;
use v4l::frameinterval::FrameIntervalEnum;
use v4l::framesize::{FrameSizeEnum, Stepwise};
use v4l::io::traits::CaptureStream as _;
use v4l::video::Capture as _;
use v4l::video::capture::Parameters;
use v4l::{Device, Format, FourCC, Fraction};

use crate::ratelimit::gated;
use crate::{CameraHost, CameraInfo, FrameCallback, MAX_FRAME_BYTES, Mode, PixelFormat, RunningCapture};

/// Modes kept per camera while probing; `advertised_modes` offers at most 32 of them anyway.
const MAX_PROBED_MODES: usize = 1024;
/// Sizes tried on cameras that report a size *range* instead of a list.
const COMMON_SIZES: [(u32, u32); 7] =
    [(1920, 1080), (1280, 720), (960, 540), (800, 600), (640, 480), (640, 360), (320, 240)];

/// The frame sizes to probe for a camera that reports a stepwise (or continuous) size range.
///
/// Expanding the whole range, as `v4l`'s `to_discrete` does, is millions of sizes for a
/// continuous range (one ioctl each) and panics on a zero step, so only the usual video sizes
/// that lie on the driver's grid are considered; if none does, the largest and smallest it has.
fn stepwise_sizes(s: &Stepwise) -> Vec<(u32, u32)> {
    let on_grid =
        |v: u32, min: u32, max: u32, step: u32| (min..=max).contains(&v) && (v - min).is_multiple_of(step.max(1));
    let mut sizes: Vec<(u32, u32)> = COMMON_SIZES
        .into_iter()
        .filter(|&(w, h)| {
            on_grid(w, s.min_width, s.max_width, s.step_width) && on_grid(h, s.min_height, s.max_height, s.step_height)
        })
        .collect();
    if sizes.is_empty() && s.min_width <= s.max_width && s.min_height <= s.max_height {
        sizes.push((s.max_width, s.max_height));
        if (s.min_width, s.min_height) != (s.max_width, s.max_height) {
            sizes.push((s.min_width, s.min_height));
        }
    }
    sizes
}

/// Exact byte length of one packed YUYV frame, if it is a size we would ever pass on.
fn yuyv_frame_len(width: u32, height: u32) -> Option<usize> {
    let len = u64::from(width).checked_mul(u64::from(height))?.checked_mul(2)?;
    usize::try_from(len).ok().filter(|len| *len <= MAX_FRAME_BYTES)
}

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
            gated!(warn, error = %e, "Could not set camera frame rate; using the driver default");
        }
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let id = camera.id.clone();
        let frame_len = match mode.format {
            PixelFormat::Yuyv => Some(yuyv_frame_len(mode.width, mode.height).context("camera frame size too large")?),
            PixelFormat::Mjpeg => None,
        };
        let thread = std::thread::Builder::new()
            .name("bastion-camera".into())
            .spawn(move || {
                if let Err(e) = capture_loop(&dev, &s, frame_len, on_frame) {
                    gated!(warn, camera = %id, error = %e, "Camera capture stopped");
                }
            })
            .context("spawn camera thread")?;
        gated!(info, camera = %camera.id, ?mode, "Camera capture started");
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
            None => data.len() <= MAX_FRAME_BYTES && data.starts_with(&[0xFF, 0xD8]),
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
            let sizes = match size.size {
                FrameSizeEnum::Discrete(d) => vec![(d.width, d.height)],
                FrameSizeEnum::Stepwise(s) => stepwise_sizes(&s),
            };
            for (width, height) in sizes {
                for iv in dev.enum_frameintervals(desc.fourcc, width, height).unwrap_or_default() {
                    // Interval = seconds per frame, so fps = denominator / numerator.
                    let (num, den) = match iv.interval {
                        FrameIntervalEnum::Discrete(f) => (f.denominator, f.numerator),
                        FrameIntervalEnum::Stepwise(s) => (s.min.denominator, s.min.numerator),
                    };
                    if num > 0 && den > 0 && modes.len() < MAX_PROBED_MODES {
                        modes.push(Mode { format, width, height, fps_num: num, fps_den: den });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn range(w: (u32, u32, u32), h: (u32, u32, u32)) -> Stepwise {
        Stepwise { min_width: w.0, max_width: w.1, step_width: w.2, min_height: h.0, max_height: h.1, step_height: h.2 }
    }

    #[test]
    fn continuous_size_ranges_yield_a_handful_of_common_sizes() {
        // A capture card: any size from 2×2 to 8192×8192. Expanding that is 67 million sizes.
        let sizes = stepwise_sizes(&range((2, 8192, 1), (2, 8192, 1)));
        assert_eq!(sizes, COMMON_SIZES);
        // A zero step (which `step_by` panics on) is treated as 1.
        assert_eq!(stepwise_sizes(&range((2, 8192, 0), (2, 8192, 0))), COMMON_SIZES);
    }

    #[test]
    fn stepwise_sizes_respect_the_grid_and_limits() {
        // 16-pixel grid up to 1280×720: 1920×1080 is out of range, 960×540 is off the grid.
        let sizes = stepwise_sizes(&range((160, 1280, 16), (120, 720, 8)));
        assert_eq!(sizes, [(1280, 720), (800, 600), (640, 480), (640, 360), (320, 240)]);
        // Nothing usual fits: fall back to the extremes rather than offering nothing.
        assert_eq!(stepwise_sizes(&range((100, 300, 100), (100, 300, 100))), [(300, 300), (100, 100)]);
        assert_eq!(stepwise_sizes(&range((100, 100, 1), (100, 100, 1))), [(100, 100)]);
        // An inverted range has no sizes at all.
        assert!(stepwise_sizes(&range((500, 100, 1), (500, 100, 1))).is_empty());
    }

    #[test]
    fn yuyv_frame_length_is_checked() {
        assert_eq!(yuyv_frame_len(640, 480), Some(614_400));
        assert_eq!(yuyv_frame_len(65_536, 65_536), None); // wraps to 0 in 32 bits
        assert_eq!(yuyv_frame_len(u32::MAX, u32::MAX), None);
        assert_eq!(yuyv_frame_len(4096, 4096), None); // 32 MB: never offered, never accepted
    }
}
