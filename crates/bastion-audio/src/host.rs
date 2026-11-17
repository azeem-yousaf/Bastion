//! Audio device abstraction. The production implementation talks to PulseAudio's protocol,
//! which PipeWire serves natively (pipewire-pulse); tests use an in-memory host.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use libpulse_binding::def::BufferAttr;
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;

pub const APP_NAME: &str = "Bastion Remote Desktop";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmSpec {
    pub rate: u32,
    pub channels: u8,
}

impl PcmSpec {
    pub fn bytes_per_frame(self) -> usize {
        usize::from(self.channels) * 2
    }
    pub fn duration_of_samples(self, samples: usize) -> Duration {
        let frames = samples / usize::from(self.channels.max(1));
        Duration::from_micros(frames as u64 * 1_000_000 / u64::from(self.rate.max(1)))
    }
    pub fn samples_for(self, d: Duration) -> usize {
        (d.as_micros() as u64 * u64::from(self.rate) / 1_000_000) as usize * usize::from(self.channels)
    }
}

pub trait PlaybackDevice: Send {
    /// Blocking write of interleaved S16 samples.
    fn write(&mut self, samples: &[i16]) -> Result<()>;
    /// Audio queued inside the sound server / hardware.
    fn latency(&self) -> Duration;
}

pub trait CaptureDevice: Send {
    /// Blocking read filling `buf` completely with interleaved S16LE bytes.
    fn read(&mut self, buf: &mut [u8]) -> Result<()>;
}

pub trait AudioHost: Send + Sync + 'static {
    fn open_playback(&self, device: Option<&str>, spec: PcmSpec, latency: Duration) -> Result<Box<dyn PlaybackDevice>>;
    fn open_capture(
        &self,
        device: Option<&str>,
        spec: PcmSpec,
        fragment_bytes: usize,
    ) -> Result<Box<dyn CaptureDevice>>;
}

/// PulseAudio / PipeWire host.
#[derive(Debug, Default, Clone, Copy)]
pub struct PulseHost;

fn pa_spec(spec: PcmSpec) -> Result<Spec> {
    let s = Spec { format: Format::S16le, channels: spec.channels, rate: spec.rate };
    if !s.is_valid() {
        return Err(anyhow!("invalid sample spec {spec:?}"));
    }
    Ok(s)
}

struct PulsePlayback(Simple);
struct PulseCapture(Simple);

impl PlaybackDevice for PulsePlayback {
    fn write(&mut self, samples: &[i16]) -> Result<()> {
        // SAFETY-free reinterpretation: S16LE on little-endian hosts is the native layout.
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        self.0.write(&bytes).map_err(|e| anyhow!("pulse write: {e}"))
    }
    fn latency(&self) -> Duration {
        self.0.get_latency().map(|us| Duration::from_micros(us.0)).unwrap_or_default()
    }
}

impl CaptureDevice for PulseCapture {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        self.0.read(buf).map_err(|e| anyhow!("pulse read: {e}"))
    }
}

impl AudioHost for PulseHost {
    fn open_playback(&self, device: Option<&str>, spec: PcmSpec, latency: Duration) -> Result<Box<dyn PlaybackDevice>> {
        let ss = pa_spec(spec)?;
        let tlength = (ss.usec_to_bytes(libpulse_binding::time::MicroSeconds(latency.as_micros() as u64))) as u32;
        let attr = BufferAttr { maxlength: u32::MAX, tlength, prebuf: u32::MAX, minreq: u32::MAX, fragsize: u32::MAX };
        let s = Simple::new(None, APP_NAME, Direction::Playback, device, "Remote audio", &ss, None, Some(&attr))
            .map_err(|e| anyhow!("{e}"))
            .with_context(|| format!("open playback device {}", device.unwrap_or("(default)")))?;
        Ok(Box::new(PulsePlayback(s)))
    }

    fn open_capture(
        &self,
        device: Option<&str>,
        spec: PcmSpec,
        fragment_bytes: usize,
    ) -> Result<Box<dyn CaptureDevice>> {
        let ss = pa_spec(spec)?;
        let attr = BufferAttr {
            maxlength: u32::MAX,
            tlength: u32::MAX,
            prebuf: u32::MAX,
            minreq: u32::MAX,
            fragsize: u32::try_from(fragment_bytes).unwrap_or(u32::MAX),
        };
        let s = Simple::new(None, APP_NAME, Direction::Record, device, "Microphone to remote", &ss, None, Some(&attr))
            .map_err(|e| anyhow!("{e}"))
            .with_context(|| format!("open capture device {}", device.unwrap_or("(default)")))?;
        Ok(Box::new(PulseCapture(s)))
    }
}
