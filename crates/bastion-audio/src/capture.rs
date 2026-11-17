//! Local microphone → remote session (MS-RDPEAI AUDIO_INPUT), via PulseAudio/PipeWire.
//!
//! Selecting PipeWire's echo-cancel source as the input device gives hardware-free echo
//! cancellation when using speakers instead of a headset.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironrdp_rdpeai::AudioFormat;
use ironrdp_rdpeai::client::{AudioPacketSink, RdpeaiCaptureHandler};
use ironrdp_rdpeai::pdu::{OpenReplyPdu, pcm_format};
use ironrdp_rdpsnd::codec::AudioEncoder;
use tracing::{debug, info, warn};

use crate::host::{AudioHost, PcmSpec, PulseHost};

#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Pulse source name; `None` = default microphone.
    pub device: Option<String>,
}

const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

use crate::format::is_pcm16;

pub fn is_capturable(f: &AudioFormat) -> bool {
    (1..=2).contains(&f.n_channels)
        && (8_000..=48_000).contains(&f.n_samples_per_sec)
        && (is_pcm16(f) || AudioEncoder::supports(&crate::format::normalize(f)))
}

struct Running {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    spec: PcmSpec,
    packet_size: usize,
    encoder: Arc<Mutex<Option<AudioEncoder>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

type SharedSink = Arc<Mutex<AudioPacketSink>>;

pub struct PulseCapture {
    host: Arc<dyn AudioHost>,
    opts: CaptureOptions,
    formats: Vec<AudioFormat>,
    running: Option<Running>,
    /// Kept so capture can be restarted when the server changes format mid-stream.
    sink: Option<SharedSink>,
}

/// Converts a packet size between PCM shapes, preserving its duration.
pub fn rescale_packet(bytes: usize, from: PcmSpec, to: PcmSpec) -> usize {
    let frames = bytes / from.bytes_per_frame().max(1);
    let frames = (frames as u64 * u64::from(to.rate) / u64::from(from.rate.max(1))).max(1) as usize;
    frames * to.bytes_per_frame()
}

fn describe(f: &AudioFormat) -> String {
    let n = crate::format::normalize(f);
    format!("{:?}/{}ch/{}Hz/{}bit", n.format, n.n_channels, n.n_samples_per_sec, n.bits_per_sample)
}

impl PulseCapture {
    pub fn new(opts: CaptureOptions) -> Self {
        Self::with_host(Arc::new(PulseHost), opts)
    }

    pub fn with_host(host: Arc<dyn AudioHost>, opts: CaptureOptions) -> Self {
        let formats = vec![
            pcm_format(2, 44_100, 16),
            pcm_format(1, 44_100, 16),
            pcm_format(2, 48_000, 16),
            pcm_format(1, 48_000, 16),
            pcm_format(1, 22_050, 16),
            pcm_format(1, 16_000, 16),
            pcm_format(1, 8_000, 16),
        ];
        Self { host, opts, formats, running: None, sink: None }
    }

    fn encoder_for(encode: &AudioFormat) -> Result<Option<AudioEncoder>, String> {
        let n = crate::format::normalize(encode);
        if is_pcm16(&n) { Ok(None) } else { AudioEncoder::new(&n).map(Some).map_err(|e| e.to_string()) }
    }

    /// Starts the capture thread; returns an HRESULT.
    fn start(&mut self, spec: PcmSpec, packet_size: usize, encoder: Option<AudioEncoder>, sink: SharedSink) -> i32 {
        self.running = None;
        let encoder = Arc::new(Mutex::new(encoder));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = sync_channel::<Result<(), String>>(1);
        let host = self.host.clone();
        let device = self.opts.device.clone();
        let (stop2, enc2) = (stop.clone(), encoder.clone());

        let thread = std::thread::Builder::new().name("bastion-mic".into()).spawn(move || {
            let mut dev = match host.open_capture(device.as_deref(), spec, packet_size) {
                Ok(d) => {
                    let _ = ready_tx.send(Ok(()));
                    d
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("{e:#}")));
                    return;
                }
            };
            let mut buf = vec![0u8; packet_size];
            let mut pcm: Vec<i16> = Vec::new();
            let mut out = Vec::new();
            let mut sent = 0u64;
            while !stop2.load(Ordering::Relaxed) {
                if let Err(e) = dev.read(&mut buf) {
                    warn!(error = %e, "Microphone read failed; reopening");
                    std::thread::sleep(Duration::from_millis(300));
                    if let Ok(d) = host.open_capture(device.as_deref(), spec, packet_size) {
                        dev = d;
                    }
                    continue;
                }
                if stop2.load(Ordering::Relaxed) {
                    break;
                }
                let packet = {
                    let mut enc = enc2.lock().unwrap_or_else(|p| p.into_inner());
                    match enc.as_mut() {
                        None => buf.clone(),
                        Some(encoder) => {
                            pcm.clear();
                            pcm.extend(buf.as_chunks::<2>().0.iter().map(|b| i16::from_le_bytes(*b)));
                            out.clear();
                            encoder.encode(&pcm, &mut out);
                            std::mem::take(&mut out)
                        }
                    }
                };
                if packet.is_empty() {
                    continue; // block codec still buffering
                }
                (sink.lock().unwrap_or_else(|p| p.into_inner()))(packet);
                sent += 1;
                if sent == 1 || sent.is_multiple_of(500) {
                    debug!(packets = sent, "Microphone audio sent");
                }
            }
        });
        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "Cannot spawn microphone thread");
                return OpenReplyPdu::E_FAIL;
            }
        };
        let running = Running { stop, thread: Some(thread), spec, packet_size, encoder };
        match ready_rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(())) => {
                info!(
                    device = self.opts.device.as_deref().unwrap_or("default"),
                    ?spec,
                    packet_size,
                    "Microphone redirection started"
                );
                self.running = Some(running);
                OpenReplyPdu::S_OK
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Cannot open microphone");
                OpenReplyPdu::E_FAIL
            }
            Err(_) => {
                warn!("Timed out opening microphone");
                OpenReplyPdu::E_FAIL
            }
        }
    }
}

impl RdpeaiCaptureHandler for PulseCapture {
    fn supported_formats(&self) -> &[AudioFormat] {
        &self.formats
    }

    fn choose_formats(&self, server_formats: &[AudioFormat]) -> Vec<AudioFormat> {
        let chosen: Vec<_> = server_formats.iter().filter(|f| is_capturable(f)).cloned().collect();
        info!(offered = server_formats.len(), accepted = chosen.len(), "Microphone formats negotiated");
        debug!(offered = ?server_formats.iter().map(describe).collect::<Vec<_>>(), "Server microphone formats");
        chosen
    }

    fn open(
        &mut self,
        capture_format: &AudioFormat,
        encode_format: &AudioFormat,
        packet_size: usize,
        sink: AudioPacketSink,
    ) -> i32 {
        info!(capture = %describe(capture_format), encode = %describe(encode_format), packet_size, "Server opened microphone");
        if !is_pcm16(capture_format) || packet_size == 0 {
            warn!(capture = %describe(capture_format), "Unsupported microphone capture format");
            return OpenReplyPdu::E_FAIL;
        }
        let encoder = match Self::encoder_for(encode_format) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Unsupported microphone encoding");
                return OpenReplyPdu::E_FAIL;
            }
        };
        let capture_spec =
            PcmSpec { rate: capture_format.n_samples_per_sec, channels: capture_format.n_channels as u8 };
        // When the server wants a compressed encoding at a different rate/channel count (Windows
        // typically asks for MS-ADPCM 22.05 kHz mono), record directly in that shape — the sound
        // server resamples/downmixes — keeping the packet duration the server asked for.
        let (spec, packet_size) = if encoder.is_some() {
            let enc = crate::format::normalize(encode_format);
            let spec = PcmSpec { rate: enc.n_samples_per_sec, channels: enc.n_channels as u8 };
            (spec, rescale_packet(packet_size, capture_spec, spec))
        } else {
            (capture_spec, packet_size)
        };
        let sink: SharedSink = Arc::new(Mutex::new(sink));
        self.sink = Some(sink.clone());
        self.start(spec, packet_size, encoder, sink)
    }

    fn set_format(&mut self, encode_format: &AudioFormat, _packet_size: usize) -> bool {
        info!(encode = %describe(encode_format), "Server changed microphone format");
        let (Some(r), Some(sink)) = (&self.running, self.sink.clone()) else { return false };
        let encoder = match Self::encoder_for(encode_format) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Unsupported microphone encoding");
                return false;
            }
        };
        let new_spec = PcmSpec { rate: encode_format.n_samples_per_sec, channels: encode_format.n_channels as u8 };
        if new_spec == r.spec {
            *r.encoder.lock().unwrap_or_else(|p| p.into_inner()) = encoder;
            return true;
        }
        // Different rate/channels: restart capture in the new format, keeping packet duration.
        let packet_size = rescale_packet(r.packet_size, r.spec, new_spec);
        self.start(new_spec, packet_size, encoder, sink) == OpenReplyPdu::S_OK
    }

    fn close(&mut self) {
        self.sink = None;
        if self.running.take().is_some() {
            info!("Microphone redirection stopped");
        }
    }
}
