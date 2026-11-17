//! Webcam redirection (MS-RDPECAM) for Bastion.
//!
//! The protocol lives in `ironrdp-rdpecam`; this crate supplies the Linux side: a [`CameraHost`]
//! that enumerates and captures local cameras (V4L2 in production, an in-memory fake in tests)
//! and [`RdpCamera`], the `CameraBackend` that feeds captured frames to the remote session.
//!
//! Frames are passed through as the camera produces them: MJPG when the camera offers it
//! (practically every UVC webcam), otherwise uncompressed YUYV at modest sizes. Nothing is
//! re-encoded.

mod backend;
mod v4l2;

use std::sync::Arc;

pub use backend::{CameraChannels, RdpCamera, camera_channels};
pub use ironrdp_rdpecam::{ENUMERATION_CHANNEL_NAME, SampleUplink};
pub use v4l2::V4l2Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PixelFormat {
    Mjpeg,
    Yuyv,
}

/// One capture mode a camera supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mode {
    pub format: PixelFormat,
    pub width: u32,
    pub height: u32,
    /// Frames per second as a fraction (`fps_num / fps_den`).
    pub fps_num: u32,
    pub fps_den: u32,
}

impl Mode {
    pub fn fps(&self) -> f64 {
        f64::from(self.fps_num) / f64::from(self.fps_den.max(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraInfo {
    /// Host-specific identifier (a `/dev/videoN` path for V4L2).
    pub id: String,
    /// Shown to the remote side, e.g. "Logitech BRIO".
    pub name: String,
    /// Everything the camera can produce, unfiltered.
    pub modes: Vec<Mode>,
}

/// Receives each captured frame (one complete JPEG, or one packed YUYV image).
pub type FrameCallback = Box<dyn FnMut(&[u8]) + Send>;

/// A running capture. Dropping it stops the camera.
pub trait RunningCapture: Send {}

pub trait CameraHost: Send + Sync + 'static {
    /// Cameras that can be redirected (capture devices offering MJPG or YUYV).
    fn cameras(&self) -> Vec<CameraInfo>;
    /// Starts capturing `mode`. Must return promptly; frames arrive on a capture thread.
    fn start(
        &self,
        camera: &CameraInfo,
        mode: Mode,
        on_frame: FrameCallback,
    ) -> anyhow::Result<Box<dyn RunningCapture>>;
}

pub fn default_host() -> Arc<dyn CameraHost> {
    Arc::new(V4l2Host)
}

/// Largest uncompressed (YUYV) frame we offer: raw video is ~150 Mbit/s even at 640×480/30.
const MAX_YUYV_PIXELS: u32 = 640 * 480;
/// Largest MJPG frame we offer; beyond 1080p only costs bandwidth for a video call.
const MAX_MJPG_HEIGHT: u32 = 1080;
const MAX_ADVERTISED_MODES: usize = 32;
/// Video calls run at 30 fps; faster modes (some webcams do 60–120) only cost bandwidth.
const TARGET_FPS: f64 = 30.0;

/// Whether `a` is a better frame rate than `b`: the fastest at or below 30 fps, else the slowest.
fn better_rate(a: &Mode, b: &Mode) -> bool {
    match (a.fps() <= TARGET_FPS, b.fps() <= TARGET_FPS) {
        (true, true) => a.fps() > b.fps(),
        (true, false) => true,
        (false, true) => false,
        (false, false) => a.fps() < b.fps(),
    }
}

/// The modes offered to the remote side, best first.
///
/// MJPG only when the camera has it (YUYV would just waste bandwidth), one frame rate per size
/// (up to 30 fps), sizes capped as above, ordered by preference: 720p first (the usual video-call size),
/// then larger, then smaller.
pub fn advertised_modes(all: &[Mode]) -> Vec<Mode> {
    let has_mjpg = all.iter().any(|m| m.format == PixelFormat::Mjpeg);
    let mut best: Vec<Mode> = Vec::new();
    for m in all {
        let allowed = match m.format {
            PixelFormat::Mjpeg => m.height <= MAX_MJPG_HEIGHT,
            PixelFormat::Yuyv => !has_mjpg && m.width * m.height <= MAX_YUYV_PIXELS,
        };
        if !allowed || m.width == 0 || m.height == 0 || m.fps_num == 0 {
            continue;
        }
        match best.iter_mut().find(|b| (b.format, b.width, b.height) == (m.format, m.width, m.height)) {
            Some(b) if better_rate(m, b) => *b = *m,
            Some(_) => {}
            None => best.push(*m),
        }
    }
    let rank = |m: &Mode| {
        let pixels = m.width * m.height;
        let target = 1280 * 720;
        // At or above 720p first (closest first), then below (largest first).
        if pixels >= target { (0, pixels - target) } else { (1, target - pixels) }
    };
    best.sort_by_key(rank);
    best.truncate(MAX_ADVERTISED_MODES);
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(format: PixelFormat, width: u32, height: u32, fps: u32) -> Mode {
        Mode { format, width, height, fps_num: fps, fps_den: 1 }
    }

    #[test]
    fn prefers_mjpg_720p_and_drops_yuyv_and_huge_modes() {
        use PixelFormat::*;
        // Shaped like a Logitech BRIO.
        let all = [
            m(Yuyv, 640, 480, 30),
            m(Yuyv, 1920, 1080, 5),
            m(Mjpeg, 640, 480, 30),
            m(Mjpeg, 1280, 720, 30),
            m(Mjpeg, 1280, 720, 60),
            m(Mjpeg, 1920, 1080, 30),
            m(Mjpeg, 1920, 1080, 15),
            m(Mjpeg, 640, 480, 120),
            m(Mjpeg, 800, 600, 60),
            m(Mjpeg, 3840, 2160, 30),
            m(Mjpeg, 320, 240, 30),
        ];
        let got = advertised_modes(&all);
        assert_eq!(
            got,
            [
                m(Mjpeg, 1280, 720, 30),
                m(Mjpeg, 1920, 1080, 30),
                m(Mjpeg, 800, 600, 60), // only faster-than-30 rates available: slowest of them
                m(Mjpeg, 640, 480, 30),
                m(Mjpeg, 320, 240, 30),
            ]
        );
    }

    #[test]
    fn yuyv_only_cameras_get_small_raw_modes() {
        use PixelFormat::*;
        let got = advertised_modes(&[m(Yuyv, 1280, 720, 10), m(Yuyv, 640, 480, 30), m(Yuyv, 320, 240, 30)]);
        assert_eq!(got, [m(Yuyv, 640, 480, 30), m(Yuyv, 320, 240, 30)]);
    }

    #[test]
    fn nothing_usable_means_no_modes() {
        assert!(advertised_modes(&[]).is_empty());
        assert!(advertised_modes(&[m(PixelFormat::Yuyv, 1920, 1080, 30)]).is_empty());
    }
}
