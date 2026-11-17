//! Remote → local audio (MS-RDPEA / RDPSND), played through PulseAudio/PipeWire.
//!
//! Decoding happens on the session thread (cheap: PCM/ADPCM/G.711); a dedicated writer thread
//! owns the device and performs blocking writes. Latency is bounded: if the queue grows past
//! the high-water mark (e.g. after a network burst) whole chunks are discarded so audio stays
//! in sync with video instead of lagging forever.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use ironrdp_rdpsnd::client::RdpsndClientHandler;
use ironrdp_rdpsnd::codec::AudioDecoder;
use ironrdp_rdpsnd::pdu::{AudioFormat, AudioFormatFlags, PitchPdu, VolumePdu, WaveFormat};
use tracing::{debug, info, warn};

use crate::host::{AudioHost, PcmSpec, PulseHost};

#[derive(Debug, Clone)]
pub struct PlaybackOptions {
    /// Pulse sink name; `None` = default (follows the user's default device).
    pub device: Option<String>,
    /// Target buffering.
    pub latency: Duration,
}

impl Default for PlaybackOptions {
    fn default() -> Self {
        Self { device: None, latency: Duration::from_millis(80) }
    }
}

/// Formats we offer when the server asks for our list; PCM is lossless and decoding is free.
pub fn client_formats() -> Vec<AudioFormat> {
    let pcm = |ch: u16, rate: u32| AudioFormat {
        format: WaveFormat::PCM,
        n_channels: ch,
        n_samples_per_sec: rate,
        n_avg_bytes_per_sec: rate * u32::from(ch) * 2,
        n_block_align: ch * 2,
        bits_per_sample: 16,
        data: None,
    };
    vec![
        pcm(2, 44_100),
        pcm(2, 48_000),
        pcm(2, 22_050),
        pcm(1, 44_100),
        pcm(1, 22_050),
        pcm(2, 16_000),
        pcm(1, 16_000),
        pcm(1, 8_000),
    ]
}

/// Accepts a server format if we can decode it and the parameters are sane.
pub fn is_playable(f: &AudioFormat) -> bool {
    (1..=2).contains(&f.n_channels)
        && (8_000..=192_000).contains(&f.n_samples_per_sec)
        && AudioDecoder::supports(&crate::format::normalize(f))
}

struct Writer {
    tx: Option<SyncSender<Vec<i16>>>,
    queued_samples: Arc<AtomicUsize>,
    device_latency_us: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    spec: PcmSpec,
}

impl Writer {
    fn spawn(host: Arc<dyn AudioHost>, opts: &PlaybackOptions, spec: PcmSpec) -> Self {
        // Queue capacity in chunks; the sample-count high-water mark below is what bounds latency.
        let (tx, rx) = sync_channel::<Vec<i16>>(256);
        let queued_samples = Arc::new(AtomicUsize::new(0));
        let device_latency_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let high_water = spec.samples_for(opts.latency * 3 + Duration::from_millis(150));
        let ctx = WriterCtx {
            host,
            device: opts.device.clone(),
            latency: opts.latency,
            spec,
            rx,
            queued: queued_samples.clone(),
            dev_lat: device_latency_us.clone(),
            stop: stop.clone(),
            high_water,
        };
        let thread = std::thread::Builder::new()
            .name("bastion-playback".into())
            .spawn(move || ctx.run())
            .map_err(|e| warn!(error = %e, "Cannot spawn audio playback thread"))
            .ok();
        Self { tx: Some(tx), queued_samples, device_latency_us, stop, thread, spec }
    }

    fn push(&self, samples: Vec<i16>) {
        let n = samples.len();
        let Some(tx) = &self.tx else { return };
        self.queued_samples.fetch_add(n, Ordering::Relaxed);
        match tx.try_send(samples) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.queued_samples.fetch_sub(n, Ordering::Relaxed);
                debug!("Playback queue full; dropping audio chunk");
            }
        }
    }

    fn latency(&self) -> Duration {
        self.spec.duration_of_samples(self.queued_samples.load(Ordering::Relaxed))
            + Duration::from_micros(self.device_latency_us.load(Ordering::Relaxed))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct WriterCtx {
    host: Arc<dyn AudioHost>,
    device: Option<String>,
    latency: Duration,
    spec: PcmSpec,
    rx: Receiver<Vec<i16>>,
    queued: Arc<AtomicUsize>,
    dev_lat: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    high_water: usize,
}

impl WriterCtx {
    fn run(self) {
        let mut dev = None;
        let mut dropped = 0usize;
        while !self.stop.load(Ordering::Relaxed) {
            let chunk = match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(c) => c,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            let queued_now = self.queued.fetch_sub(chunk.len(), Ordering::Relaxed).saturating_sub(chunk.len());
            if queued_now > self.high_water {
                dropped += chunk.len();
                continue; // catch up: keep audio close to real time
            }
            if dropped > 0 {
                debug!(samples = dropped, "Dropped late audio to stay in sync");
                dropped = 0;
            }
            if dev.is_none() {
                match self.host.open_playback(self.device.as_deref(), self.spec, self.latency) {
                    Ok(d) => {
                        info!(device = self.device.as_deref().unwrap_or("default"), spec = ?self.spec, "Audio playback started");
                        dev = Some(d);
                    }
                    Err(e) => {
                        warn!(error = %e, "Cannot open audio output; retrying");
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                }
            }
            if let Some(d) = dev.as_mut() {
                if let Err(e) = d.write(&chunk) {
                    warn!(error = %e, "Audio output failed (device removed?); reopening");
                    dev = None;
                } else {
                    self.dev_lat.store(d.latency().as_micros() as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

pub struct PulsePlayback {
    host: Arc<dyn AudioHost>,
    opts: PlaybackOptions,
    formats: Vec<AudioFormat>,
    decoder: Option<(AudioFormat, AudioDecoder)>,
    writer: Option<Writer>,
    gain: (f32, f32),
    scratch: Vec<i16>,
}

impl core::fmt::Debug for PulsePlayback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PulsePlayback").field("opts", &self.opts).field("gain", &self.gain).finish_non_exhaustive()
    }
}

impl PulsePlayback {
    pub fn new(opts: PlaybackOptions) -> Self {
        Self::with_host(Arc::new(PulseHost), opts)
    }

    pub fn with_host(host: Arc<dyn AudioHost>, opts: PlaybackOptions) -> Self {
        Self {
            host,
            opts,
            formats: client_formats(),
            decoder: None,
            writer: None,
            gain: (1.0, 1.0),
            scratch: Vec::new(),
        }
    }

    fn ensure_pipeline(&mut self, format: &AudioFormat) -> bool {
        if self.decoder.as_ref().is_some_and(|(f, _)| f == format) {
            return true;
        }
        let dec = match AudioDecoder::new(&crate::format::normalize(format)) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, ?format, "Unsupported audio format from server");
                return false;
            }
        };
        let spec = PcmSpec { rate: format.n_samples_per_sec, channels: format.n_channels as u8 };
        if self.writer.as_ref().is_none_or(|w| w.spec != spec) {
            self.writer = Some(Writer::spawn(self.host.clone(), &self.opts, spec));
        }
        info!(format = ?crate::format::normalize(format).format, rate = format.n_samples_per_sec, channels = format.n_channels, "Remote audio stream started");
        self.decoder = Some((format.clone(), dec));
        true
    }
}

impl RdpsndClientHandler for PulsePlayback {
    fn get_flags(&self) -> AudioFormatFlags {
        AudioFormatFlags::VOLUME
    }

    fn get_formats(&self) -> &[AudioFormat] {
        &self.formats
    }

    fn choose_formats(&self, server_formats: &[AudioFormat]) -> Vec<AudioFormat> {
        let chosen: Vec<_> = server_formats.iter().filter(|f| is_playable(f)).cloned().collect();
        let offered: Vec<String> = server_formats
            .iter()
            .map(|f| format!("{:?}/{}ch/{}Hz/{}bit", f.format, f.n_channels, f.n_samples_per_sec, f.bits_per_sample))
            .collect();
        if chosen.is_empty() {
            warn!(?offered, "Server offered no playable audio format");
        } else {
            info!(offered = offered.len(), accepted = chosen.len(), "Audio formats negotiated");
            debug!(?offered, "Server audio formats");
        }
        chosen
    }

    fn wave(&mut self, format: &AudioFormat, _ts: u32, data: Cow<'_, [u8]>) {
        if !self.ensure_pipeline(format) {
            return;
        }
        let Some((_, dec)) = self.decoder.as_mut() else { return };
        self.scratch.clear();
        if let Err(e) = dec.decode(&data, &mut self.scratch) {
            debug!(error = %e, "Audio decode error (partial chunk kept)");
        }
        if self.gain != (1.0, 1.0) {
            let stereo = format.n_channels == 2;
            for (i, s) in self.scratch.iter_mut().enumerate() {
                let g = if stereo && i % 2 == 1 { self.gain.1 } else { self.gain.0 };
                *s = (f32::from(*s) * g) as i16;
            }
        }
        if let Some(w) = &self.writer {
            w.push(std::mem::take(&mut self.scratch));
        }
    }

    fn playback_latency(&self) -> Duration {
        self.writer.as_ref().map(Writer::latency).unwrap_or_default()
    }

    fn set_volume(&mut self, volume: VolumePdu) {
        self.gain = (f32::from(volume.volume_left) / 65535.0, f32::from(volume.volume_right) / 65535.0);
    }

    fn set_pitch(&mut self, _pitch: PitchPdu) {}

    fn close(&mut self) {
        self.writer = None;
        self.decoder = None;
    }
}
