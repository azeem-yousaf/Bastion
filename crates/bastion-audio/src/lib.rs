//! Native PulseAudio/PipeWire audio for Bastion: remote audio playback and microphone redirection.

pub mod capture;
pub mod devices;
pub mod format;
pub mod host;
pub mod playback;
mod ratelimit;

pub use capture::{CaptureOptions, PulseCapture};
pub use devices::{AudioDevice, DeviceList, list_devices};
pub use host::{AudioHost, CaptureDevice, PcmSpec, PlaybackDevice, PulseHost};
pub use playback::{PlaybackOptions, PulsePlayback};
