//! The `CameraBackend` that connects a local camera to the RDPECAM device channel.

use std::sync::{Arc, Mutex};

use ironrdp_dvc::DrdynvcClient;
use ironrdp_rdpecam::{
    CameraBackend, CameraRedirectionSession, DeviceChannelListener, DeviceDescriptor, EnumerationClient, ErrorCode,
    MediaFormat, MediaType, RedirectedDevice, SampleDelivery, SampleSink, SampleUplink, StartStreamInfo,
    StreamDescription,
};
use tracing::{debug, warn};

use crate::ratelimit::gated;
use crate::{CameraHost, CameraInfo, Mode, PixelFormat, RunningCapture, advertised_modes};

/// The only stream we expose: the colour video stream.
const STREAM: u8 = 0;

fn media_type(m: &Mode) -> MediaType {
    let (format, flags) = match m.format {
        PixelFormat::Mjpeg => (MediaFormat::Mjpg, MediaType::DECODING_REQUIRED),
        PixelFormat::Yuyv => (MediaFormat::Yuy2, 0),
    };
    MediaType {
        format,
        width: m.width,
        height: m.height,
        frame_rate_numerator: m.fps_num,
        frame_rate_denominator: m.fps_den,
        pixel_aspect_ratio_numerator: 1,
        pixel_aspect_ratio_denominator: 1,
        flags,
    }
}

/// Frames are handed to the sink as they arrive; one that arrives while the server has no
/// outstanding request is kept (only the newest) and sent on the next request.
#[derive(Default)]
struct Delivery {
    sink: Option<SampleSink>,
    pending: Option<Vec<u8>>,
}

impl Delivery {
    fn offer(&mut self, frame: Vec<u8>) {
        let Some(sink) = &self.sink else { return };
        if frame.len() > crate::MAX_FRAME_BYTES {
            bastion_metrics::CAMERA_DROPPED.incr();
            return;
        }
        let len = frame.len() as u64;
        self.pending = match sink.send_sample(STREAM, frame.clone()) {
            SampleDelivery::NotRequested | SampleDelivery::Failed => Some(frame),
            SampleDelivery::Sent => {
                bastion_metrics::CAMERA_FRAMES.incr();
                bastion_metrics::CAMERA_TX.add(len);
                None
            }
            SampleDelivery::Rejected | SampleDelivery::Stopped => None,
        };
    }
}

/// One redirected camera.
pub struct RdpCamera {
    host: Arc<dyn CameraHost>,
    camera: CameraInfo,
    modes: Vec<Mode>,
    current: Mode,
    capture: Option<Box<dyn RunningCapture>>,
    delivery: Arc<Mutex<Delivery>>,
}

impl RdpCamera {
    /// `None` if the camera has no mode we can offer.
    pub fn new(host: Arc<dyn CameraHost>, camera: CameraInfo) -> Option<Self> {
        let modes = advertised_modes(&camera.modes);
        let current = *modes.first()?;
        Some(Self { host, camera, modes, current, capture: None, delivery: Arc::default() })
    }

    fn stop(&mut self) {
        // Drop the sink first so a frame racing the shutdown isn't sent.
        *self.delivery.lock().unwrap_or_else(|p| p.into_inner()) = Delivery::default();
        if self.capture.take().is_some() {
            gated!(info, camera = %self.camera.name, "Remote stopped the camera");
        }
    }
}

impl CameraBackend for RdpCamera {
    fn activate(&mut self) -> Result<(), ErrorCode> {
        debug!(camera = %self.camera.name, "Camera activated");
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), ErrorCode> {
        self.stop();
        Ok(())
    }

    fn streams(&mut self) -> Result<Vec<StreamDescription>, ErrorCode> {
        Ok(vec![StreamDescription::color(true, true)])
    }

    fn media_types(&mut self, stream_index: u8) -> Result<Vec<MediaType>, ErrorCode> {
        if stream_index != STREAM {
            return Err(ErrorCode::InvalidStreamNumber);
        }
        Ok(self.modes.iter().map(media_type).collect())
    }

    fn current_media_type(&mut self, stream_index: u8) -> Result<MediaType, ErrorCode> {
        if stream_index != STREAM {
            return Err(ErrorCode::InvalidStreamNumber);
        }
        Ok(media_type(&self.current))
    }

    fn start_streams(&mut self, streams: &[StartStreamInfo], sink: SampleSink) -> Result<(), ErrorCode> {
        let [info] = streams else { return Err(ErrorCode::InvalidStreamNumber) };
        if info.stream_index != STREAM {
            return Err(ErrorCode::InvalidStreamNumber);
        }
        let mode = *self.modes.iter().find(|m| media_type(m) == info.media_type).ok_or(ErrorCode::InvalidMediaType)?;

        // A V4L2 device streams one format at a time, so the old capture must stop before the new
        // one opens. If the new one then fails, the server gets an error and the camera is off.
        let previous =
            (self.capture.take(), std::mem::take(&mut *self.delivery.lock().unwrap_or_else(|p| p.into_inner())));
        let delivery = Arc::new(Mutex::new(Delivery { sink: Some(sink), pending: None }));
        let d = delivery.clone();
        let on_frame = Box::new(move |frame: &[u8]| {
            // Checked before copying: an oversized frame is never even duplicated.
            if frame.len() > crate::MAX_FRAME_BYTES {
                bastion_metrics::CAMERA_DROPPED.incr();
                return;
            }
            d.lock().unwrap_or_else(|p| p.into_inner()).offer(frame.to_vec());
        });
        drop(previous.0);
        match self.host.start(&self.camera, mode, on_frame) {
            Ok(capture) => {
                gated!(info, camera = %self.camera.name, ?mode, "Remote started the camera");
                self.capture = Some(capture);
                self.delivery = delivery;
                self.current = mode;
                Ok(())
            }
            Err(e) => {
                gated!(warn, camera = %self.camera.name, error = format!("{e:#}"), "Could not start the camera");
                Err(ErrorCode::InvalidRequest)
            }
        }
    }

    fn stop_streams(&mut self) -> Result<(), ErrorCode> {
        self.stop();
        Ok(())
    }

    fn sample_requested(&mut self, stream_index: u8) {
        if stream_index != STREAM {
            return;
        }
        let mut d = self.delivery.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(frame) = d.pending.take() {
            d.offer(frame);
        }
    }

    fn shutdown(&mut self) {
        self.stop();
    }
}

/// The dynamic channels to register for camera redirection.
pub struct CameraChannels {
    session: CameraRedirectionSession,
    redirected: Vec<RedirectedDevice>,
    pub devices: Vec<DeviceChannelListener<RdpCamera>>,
    /// Names of the redirected cameras, for logging/notices.
    pub names: Vec<String>,
}

impl CameraChannels {
    /// A fresh enumeration-channel processor.
    pub fn enumerator(&self) -> EnumerationClient {
        Self::make_enumerator(&self.session, &self.redirected)
    }

    fn make_enumerator(session: &CameraRedirectionSession, redirected: &[RedirectedDevice]) -> EnumerationClient {
        // The same device list was already validated when these channels were built.
        session.enumeration_client(redirected.to_vec()).expect("camera list validated in camera_channels")
    }

    /// Registers the channels with the DRDYNVC client.
    ///
    /// The enumeration channel is registered as a *factory*: Windows closes and reopens every
    /// dynamic channel when logon hands over to the user's desktop, and a single pre-built
    /// processor can't be opened a second time (Windows would then see no camera).
    pub fn register(self, mut drdynvc: DrdynvcClient) -> DrdynvcClient {
        let Self { session, redirected, devices, .. } = self;
        drdynvc = drdynvc.with_dynamic_channel_factory(ironrdp_rdpecam::ENUMERATION_CHANNEL_NAME, move || {
            Self::make_enumerator(&session, &redirected)
        });
        for device in devices {
            drdynvc = drdynvc.with_listener(device);
        }
        drdynvc
    }
}

/// Builds the RDPECAM channels for every usable local camera. `None` when there are none.
///
/// `uplink` carries captured samples into the session loop (same shape as the microphone's).
pub fn camera_channels(host: Arc<dyn CameraHost>, uplink: SampleUplink) -> Option<CameraChannels> {
    let session = CameraRedirectionSession::new();
    let mut redirected = Vec::new();
    let mut devices = Vec::new();
    let mut names = Vec::new();
    for camera in host.cameras() {
        if advertised_modes(&camera.modes).is_empty() {
            continue;
        }
        let channel = format!("RDCamera_Device_{}", redirected.len());
        let descriptor = match DeviceDescriptor::new(camera.name.clone(), channel) {
            Ok(d) => d,
            Err(e) => {
                warn!(camera = %camera.name, error = %e, "Camera name not usable for redirection");
                continue;
            }
        };
        let Ok(device) = session.select_device(descriptor) else { continue };
        let h = host.clone();
        let cam = camera.clone();
        devices.push(device.listener(move || RdpCamera::new(h.clone(), cam.clone()), uplink.clone()));
        redirected.push(device);
        names.push(camera.name);
    }
    if redirected.is_empty() {
        return None;
    }
    // Validate once up front so building more enumerators later can't fail.
    session.enumeration_client(redirected.clone()).ok()?;
    Some(CameraChannels { session, redirected, devices, names })
}
