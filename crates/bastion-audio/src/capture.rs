//! Local microphone → remote session (MS-RDPEAI AUDIO_INPUT), via PulseAudio/PipeWire.
//!
//! Selecting PipeWire's echo-cancel source as the input device gives hardware-free echo
//! cancellation when using speakers instead of a headset.
//!
//! Everything the server chooses here (capture format, encode format, packet size) is treated as
//! hostile: shapes go through [`crate::format::pcm_spec`], packet sizes are capped at
//! [`MAX_PACKET_BYTES`], and the capture thread can always be stopped within a short, fixed time.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironrdp_rdpeai::AudioFormat;
use ironrdp_rdpeai::client::{AudioPacketSink, RdpeaiCaptureHandler};
use ironrdp_rdpeai::pdu::{OpenReplyPdu, pcm_format};
use ironrdp_rdpsnd::codec::AudioEncoder;
use tracing::debug;

use crate::format::{is_pcm16, pcm_spec};
use crate::host::{AudioHost, PcmSpec, PulseHost};
use crate::ratelimit::gated;

#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Pulse source name; `None` = default microphone.
    pub device: Option<String>,
}

const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest capture packet (and so capture buffer) we ever allocate: one second of 48 kHz stereo,
/// the same bound MS-RDPEAI's Open PDU is held to.
pub const MAX_PACKET_BYTES: usize = ironrdp_rdpeai::pdu::MAX_DATA_PACKET_SIZE;

/// The device is read in slices of at most this much audio so the stop flag is seen promptly,
/// however long a packet the server asked for.
const READ_SLICE: Duration = Duration::from_millis(20);
/// How long closing or restarting capture waits for the capture thread. A thread that has not
/// finished by then (a sound server that stopped delivering audio) is detached: it exits on its
/// own as soon as its read returns, and never delivers another packet.
const JOIN_TIMEOUT: Duration = Duration::from_millis(400);
/// Capture threads that may be alive at once per [`MicThreads`] (one per session), counting
/// detached ones still stuck in a read. Further Opens are refused until they exit.
const MAX_LIVE_THREADS: usize = 3;
/// Server format lists are logged (at debug) only up to this many entries.
const MAX_LOGGED_FORMATS: usize = 16;

pub fn is_capturable(f: &AudioFormat) -> bool {
    (1..=2).contains(&f.n_channels)
        && (8_000..=48_000).contains(&f.n_samples_per_sec)
        && pcm_spec(f).is_some()
        && (is_pcm16(f) || AudioEncoder::supports(&crate::format::normalize(f)))
}

struct Running {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Disconnects when the capture thread has finished.
    done: Receiver<()>,
    spec: PcmSpec,
    packet_size: usize,
    encoder: Arc<Mutex<Option<AudioEncoder>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else { return };
        match self.done.recv_timeout(JOIN_TIMEOUT) {
            // The thread is past its loop; joining only waits for it to unwind.
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = thread.join();
            }
            // Never block the session thread on a device read: let the thread go. It checks the
            // stop flag before delivering anything, so no stale audio follows.
            Err(RecvTimeoutError::Timeout) => {
                gated!(warn, "Microphone did not stop in time; leaving it to finish in the background");
            }
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
    /// Capture threads still alive (including detached ones), shared by every channel instance
    /// of a session.
    live_threads: MicThreads,
}

/// Counts a session's live microphone capture threads. The server can close and reopen the
/// microphone channel at will, and each reopen builds a new [`PulseCapture`]; sharing one
/// counter between them keeps the [`MAX_LIVE_THREADS`] limit from being reset that way.
#[derive(Clone, Default, Debug)]
pub struct MicThreads(Arc<AtomicUsize>);

/// Converts a packet size between PCM shapes, preserving its duration. `None` when either shape
/// is degenerate (zero rate or channels) or the result would exceed [`MAX_PACKET_BYTES`].
pub fn checked_rescale_packet(bytes: usize, from: PcmSpec, to: PcmSpec) -> Option<usize> {
    let (from_frame, to_frame) = (from.bytes_per_frame(), to.bytes_per_frame());
    if from_frame == 0 || to_frame == 0 || from.rate == 0 || to.rate == 0 {
        return None;
    }
    let frames = u64::try_from(bytes / from_frame).ok()?;
    let frames = (frames.checked_mul(u64::from(to.rate))? / u64::from(from.rate)).max(1);
    let out = usize::try_from(frames.checked_mul(u64::try_from(to_frame).ok()?)?).ok()?;
    (out <= MAX_PACKET_BYTES).then_some(out)
}

/// Converts a packet size between PCM shapes, preserving its duration.
///
/// Never overflows and never returns more than [`MAX_PACKET_BYTES`]: sizes that cannot be
/// represented are clamped to the largest whole-frame packet (0 if `to` has no channels). Code
/// handling server input uses [`checked_rescale_packet`] and refuses instead.
pub fn rescale_packet(bytes: usize, from: PcmSpec, to: PcmSpec) -> usize {
    checked_rescale_packet(bytes, from, to).unwrap_or_else(|| match to.bytes_per_frame() {
        0 => 0,
        frame => MAX_PACKET_BYTES / frame * frame,
    })
}

/// Bytes read from the device per call: at most [`READ_SLICE`] of audio, whole frames, never
/// more than the packet.
fn read_slice_bytes(spec: PcmSpec, packet_size: usize) -> usize {
    let frames = (u64::from(spec.rate) * READ_SLICE.as_millis() as u64 / 1000).max(1);
    let bytes = usize::try_from(frames).unwrap_or(usize::MAX).saturating_mul(spec.bytes_per_frame().max(1));
    bytes.min(packet_size).max(1)
}

/// Sleeps for `total` unless `stop` is set first; returns whether it was.
fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) -> bool {
    let step = Duration::from_millis(20);
    let mut left = total;
    while !left.is_zero() {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        let d = left.min(step);
        std::thread::sleep(d);
        left -= d;
    }
    stop.load(Ordering::Relaxed)
}

/// Decrements the live-thread count when the capture thread ends, however it ends.
struct LiveGuard(Arc<AtomicUsize>);

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
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
        Self { host, opts, formats, running: None, sink: None, live_threads: MicThreads::default() }
    }

    /// Like [`Self::with_host`], counting capture threads in `threads` (shared across channel
    /// instances of one session).
    pub fn with_host_and_threads(host: Arc<dyn AudioHost>, opts: CaptureOptions, threads: MicThreads) -> Self {
        Self { live_threads: threads, ..Self::with_host(host, opts) }
    }

    fn encoder_for(encode: &AudioFormat) -> Result<Option<AudioEncoder>, String> {
        let n = crate::format::normalize(encode);
        if is_pcm16(&n) { Ok(None) } else { AudioEncoder::new(&n).map(Some).map_err(|e| e.to_string()) }
    }

    /// Starts the capture thread; returns an HRESULT.
    fn start(&mut self, spec: PcmSpec, packet_size: usize, encoder: Option<AudioEncoder>, sink: SharedSink) -> i32 {
        self.running = None;
        // Last line of defence: nothing below may see a degenerate shape or an unbounded size.
        if spec.rate == 0 || spec.channels == 0 || packet_size == 0 || packet_size > MAX_PACKET_BYTES {
            bastion_metrics::AUDIO_REJECTED.incr();
            return OpenReplyPdu::E_FAIL;
        }
        if self.live_threads.0.load(Ordering::Relaxed) >= MAX_LIVE_THREADS {
            bastion_metrics::AUDIO_REJECTED.incr();
            gated!(warn, "Microphone is still busy stopping; refusing to open it again");
            return OpenReplyPdu::E_FAIL;
        }
        let encoder = Arc::new(Mutex::new(encoder));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = sync_channel::<Result<(), String>>(1);
        let (done_tx, done_rx) = sync_channel::<()>(1);
        let host = self.host.clone();
        let device = self.opts.device.clone();
        let (stop2, enc2) = (stop.clone(), encoder.clone());
        let slice = read_slice_bytes(spec, packet_size);
        self.live_threads.0.fetch_add(1, Ordering::Relaxed);
        let live = LiveGuard(self.live_threads.0.clone());

        let thread = std::thread::Builder::new().name("bastion-mic".into()).spawn(move || {
            // Both are dropped when the thread ends, however it ends.
            let (_live, _done) = (live, done_tx);
            let mut dev = match host.open_capture(device.as_deref(), spec, slice) {
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
            'packets: while !stop2.load(Ordering::Relaxed) {
                // Fill one packet a slice at a time so a stop request never waits for more than
                // one slice of audio, whatever packet duration the server chose.
                let mut filled = 0;
                while filled < buf.len() {
                    if stop2.load(Ordering::Relaxed) {
                        break 'packets;
                    }
                    let end = filled.saturating_add(slice).min(buf.len());
                    if let Err(e) = dev.read(&mut buf[filled..end]) {
                        gated!(warn, error = %e, "Microphone read failed; reopening");
                        if sleep_unless_stopped(&stop2, Duration::from_millis(300)) {
                            break 'packets;
                        }
                        if let Ok(d) = host.open_capture(device.as_deref(), spec, slice) {
                            dev = d;
                        }
                        continue 'packets;
                    }
                    filled = end;
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
                bastion_metrics::MIC_PACKETS.incr();
                sent += 1;
                if sent == 1 || sent.is_multiple_of(500) {
                    debug!(packets = sent, "Microphone audio sent");
                }
            }
        });
        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                // The closure (and with it the live-thread guard) was dropped by the failed spawn.
                gated!(warn, error = %e, "Cannot spawn microphone thread");
                return OpenReplyPdu::E_FAIL;
            }
        };
        let running = Running { stop, thread: Some(thread), done: done_rx, spec, packet_size, encoder };
        match ready_rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(())) => {
                gated!(
                    info,
                    device = self.opts.device.as_deref().unwrap_or("default"),
                    ?spec,
                    packet_size,
                    "Microphone redirection started"
                );
                self.running = Some(running);
                OpenReplyPdu::S_OK
            }
            Ok(Err(e)) => {
                gated!(warn, error = %e, "Cannot open microphone");
                OpenReplyPdu::E_FAIL
            }
            Err(_) => {
                gated!(warn, "Timed out opening microphone");
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
        gated!(info, offered = server_formats.len(), accepted = chosen.len(), "Microphone formats negotiated");
        debug!(
            offered = ?server_formats.iter().take(MAX_LOGGED_FORMATS).map(describe).collect::<Vec<_>>(),
            total = server_formats.len(),
            "Server microphone formats"
        );
        chosen
    }

    fn open(
        &mut self,
        capture_format: &AudioFormat,
        encode_format: &AudioFormat,
        packet_size: usize,
        sink: AudioPacketSink,
    ) -> i32 {
        gated!(info, capture = %describe(capture_format), encode = %describe(encode_format), packet_size, "Server opened microphone");
        // The capture WAVEFORMATEX comes straight from the Open PDU; it was never negotiated, so
        // nothing has checked it yet.
        let capture_spec = match pcm_spec(capture_format) {
            Some(spec) if is_pcm16(capture_format) && (1..=MAX_PACKET_BYTES).contains(&packet_size) => spec,
            _ => {
                bastion_metrics::AUDIO_REJECTED.incr();
                gated!(warn, capture = %describe(capture_format), packet_size, "Unsupported microphone capture format");
                return OpenReplyPdu::E_FAIL;
            }
        };
        let encoder = match Self::encoder_for(encode_format) {
            Ok(e) => e,
            Err(e) => {
                bastion_metrics::AUDIO_REJECTED.incr();
                gated!(warn, error = %e, "Unsupported microphone encoding");
                return OpenReplyPdu::E_FAIL;
            }
        };
        // When the server wants a compressed encoding at a different rate/channel count (Windows
        // typically asks for MS-ADPCM 22.05 kHz mono), record directly in that shape — the sound
        // server resamples/downmixes — keeping the packet duration the server asked for.
        let shape = if encoder.is_some() {
            pcm_spec(encode_format)
                .and_then(|spec| Some((spec, checked_rescale_packet(packet_size, capture_spec, spec)?)))
        } else {
            Some((capture_spec, packet_size))
        };
        let Some((spec, packet_size)) = shape else {
            bastion_metrics::AUDIO_REJECTED.incr();
            gated!(warn, encode = %describe(encode_format), packet_size, "Unsupported microphone packet size");
            return OpenReplyPdu::E_FAIL;
        };
        let sink: SharedSink = Arc::new(Mutex::new(sink));
        self.sink = Some(sink.clone());
        self.start(spec, packet_size, encoder, sink)
    }

    fn set_format(&mut self, encode_format: &AudioFormat, _packet_size: usize) -> bool {
        gated!(info, encode = %describe(encode_format), "Server changed microphone format");
        let (Some(r), Some(sink)) = (&self.running, self.sink.clone()) else { return false };
        let encoder = match Self::encoder_for(encode_format) {
            Ok(e) => e,
            Err(e) => {
                bastion_metrics::AUDIO_REJECTED.incr();
                gated!(warn, error = %e, "Unsupported microphone encoding");
                return false;
            }
        };
        let Some(new_spec) = pcm_spec(encode_format) else {
            bastion_metrics::AUDIO_REJECTED.incr();
            gated!(warn, encode = %describe(encode_format), "Unsupported microphone format change");
            return false;
        };
        if new_spec == r.spec {
            *r.encoder.lock().unwrap_or_else(|p| p.into_inner()) = encoder;
            return true;
        }
        // Different rate/channels: restart capture in the new format, keeping packet duration.
        let Some(packet_size) = checked_rescale_packet(r.packet_size, r.spec, new_spec) else {
            bastion_metrics::AUDIO_REJECTED.incr();
            gated!(warn, encode = %describe(encode_format), "Unsupported microphone packet size after format change");
            return false;
        };
        self.start(new_spec, packet_size, encoder, sink) == OpenReplyPdu::S_OK
    }

    fn close(&mut self) {
        self.sink = None;
        if self.running.take().is_some() {
            gated!(info, "Microphone redirection stopped");
        }
    }
}
