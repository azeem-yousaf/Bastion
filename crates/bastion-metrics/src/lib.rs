//! Performance metrics: where the time goes between the network, the decoders and the screen.
//!
//! Recording costs a handful of relaxed atomic operations — no locks, no allocation, no I/O —
//! so it is safe on every hot path (per PDU, per frame, per input event). A reporter thread
//! folds everything into **one** summary log line per interval and writes nothing at all while
//! the app is idle, so the log volume does not grow with activity.
//!
//! A line looks like:
//!
//! ```text
//! net.rx=21.4MB (2.1MB/s) net.pdus=4120 (412/s) … rdp.process[n=4120 avg=0.62 p50=0.51 p95=1.9 p99=4.1 max=12.3]ms …
//! ```
//!
//! Percentiles come from power-of-two buckets, so they are upper bounds accurate to a factor
//! of two; `avg` and `max` are exact. Any timing whose max crosses its "slow" threshold is
//! called out and the line is logged as a warning.
//!
//! Environment: `BASTION_METRICS=off` disables the reporter, `BASTION_METRICS=<seconds>` sets
//! the interval (default 10).

use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Bucket `i` (i ≥ 1) holds values in `[2^(i-1), 2^i)` µs; the last one everything above ~67 s.
const BUCKETS: usize = 28;

/// A latency distribution in microseconds.
pub struct Histogram {
    pub name: &'static str,
    slow_us: u64,
    count: AtomicU64,
    sum_us: AtomicU64,
    max_us: AtomicU64,
    slow: AtomicU64,
    buckets: [AtomicU64; BUCKETS],
}

impl Histogram {
    /// `slow_ms`: durations at or above this are counted and reported as slow.
    pub const fn new(name: &'static str, slow_ms: u64) -> Self {
        Self {
            name,
            slow_us: slow_ms * 1000,
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
            slow: AtomicU64::new(0),
            buckets: [const { AtomicU64::new(0) }; BUCKETS],
        }
    }

    pub fn record(&self, d: Duration) {
        self.record_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    }

    pub fn record_us(&self, us: u64) {
        self.count.fetch_add(1, Relaxed);
        self.sum_us.fetch_add(us, Relaxed);
        self.max_us.fetch_max(us, Relaxed);
        if us >= self.slow_us {
            self.slow.fetch_add(1, Relaxed);
        }
        self.buckets[bucket(us)].fetch_add(1, Relaxed);
    }

    /// Records the time elapsed since `start`.
    pub fn since(&self, start: Instant) {
        self.record(start.elapsed());
    }

    /// Times a closure.
    pub fn time<T>(&self, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        self.since(start);
        out
    }

    /// Records when the returned guard is dropped.
    pub fn start(&self) -> Span<'_> {
        Span { hist: self, start: Instant::now() }
    }

    fn take(&self) -> HistSnapshot {
        let mut buckets = [0u64; BUCKETS];
        for (b, a) in buckets.iter_mut().zip(&self.buckets) {
            *b = a.swap(0, Relaxed);
        }
        HistSnapshot {
            count: self.count.swap(0, Relaxed),
            sum_us: self.sum_us.swap(0, Relaxed),
            max_us: self.max_us.swap(0, Relaxed),
            slow: self.slow.swap(0, Relaxed),
            buckets,
        }
    }
}

fn bucket(us: u64) -> usize {
    ((u64::BITS - us.leading_zeros()) as usize).min(BUCKETS - 1)
}

/// Guard from [`Histogram::start`].
pub struct Span<'a> {
    hist: &'a Histogram,
    start: Instant,
}

impl Drop for Span<'_> {
    fn drop(&mut self) {
        self.hist.since(self.start);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Count,
    Bytes,
}

/// A monotonically increasing total (reported as total and rate per interval).
pub struct Counter {
    pub name: &'static str,
    unit: Unit,
    value: AtomicU64,
}

impl Counter {
    pub const fn count(name: &'static str) -> Self {
        Self { name, unit: Unit::Count, value: AtomicU64::new(0) }
    }
    pub const fn bytes(name: &'static str) -> Self {
        Self { name, unit: Unit::Bytes, value: AtomicU64::new(0) }
    }
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Relaxed);
    }
    pub fn incr(&self) {
        self.add(1);
    }
    fn take(&self) -> u64 {
        self.value.swap(0, Relaxed)
    }
}

/// Remembers when the oldest still-unhandled item was queued (e.g. input waiting for the
/// network thread), to measure queueing delay across threads without changing message types.
#[derive(Debug, Default)]
pub struct Stamp(AtomicU64);

impl Stamp {
    /// Marks "something is waiting" unless an older mark is pending.
    pub fn mark(&self) {
        // 0 means "nothing pending", so shift by one.
        let _ = self.0.compare_exchange(0, now_us() + 1, Relaxed, Relaxed);
    }

    /// Clears the mark and returns how long the oldest item waited.
    pub fn take(&self) -> Option<Duration> {
        match self.0.swap(0, Relaxed) {
            0 => None,
            t => Some(Duration::from_micros(now_us().saturating_sub(t - 1))),
        }
    }
}

fn now_us() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_micros()).unwrap_or(u64::MAX)
}

// --- The metrics -------------------------------------------------------------------------------

/// Bytes read from the server (after TLS).
pub static NET_RX: Counter = Counter::bytes("net.rx");
/// Bytes written to the server (after TLS framing, before encryption).
pub static NET_TX: Counter = Counter::bytes("net.tx");
/// PDUs received from the server.
pub static NET_PDUS: Counter = Counter::count("net.pdus");
/// Time to write one PDU to the socket (high = network back-pressure).
pub static NET_WRITE: Histogram = Histogram::new("net.write", 20);
/// Time to process one server PDU, including bitmap/RemoteFX/GFX decoding.
pub static RDP_PROCESS: Histogram = Histogram::new("rdp.process", 30);

/// Graphics updates published to the screen.
pub static FRAME_UPDATES: Counter = Counter::count("frame.updates");
/// Pixels copied into the shared framebuffer.
pub static FRAME_PIXELS: Counter = Counter::count("frame.pixels");
/// Copying a dirty rectangle into the shared framebuffer (including lock wait).
pub static FRAME_PUBLISH: Histogram = Histogram::new("frame.publish", 10);
/// From pixels decoded to pixels uploaded to the GPU (UI thread responsiveness).
pub static FRAME_LATENCY: Histogram = Histogram::new("frame.latency", 50);

/// H.264 frames decoded.
pub static VIDEO_FRAMES: Counter = Counter::count("video.frames");
/// H.264 decode of one frame (FFmpeg).
pub static VIDEO_DECODE: Histogram = Histogram::new("video.decode", 30);
/// YUV → RGBA/planar conversion of one decoded frame.
pub static VIDEO_CONVERT: Histogram = Histogram::new("video.convert", 15);
/// Hardware decoder failures that forced software decoding.
pub static VIDEO_HW_FALLBACKS: Counter = Counter::count("video.hw_fallbacks");

/// Input batches sent (key presses, mouse moves…).
pub static INPUT_BATCHES: Counter = Counter::count("input.batches");
/// Time input waited in the UI → network-thread queue.
pub static INPUT_QUEUE: Histogram = Histogram::new("input.queue", 10);
/// From input queued by the UI to written to the socket.
pub static INPUT_LATENCY: Histogram = Histogram::new("input.latency", 20);

/// Handling one window event on the UI thread.
pub static UI_EVENT: Histogram = Histogram::new("ui.event", 30);
/// Frames rendered (all windows).
pub static UI_FRAMES: Counter = Counter::count("ui.frames");
/// Bytes uploaded to GPU textures.
pub static UI_UPLOAD_BYTES: Counter = Counter::bytes("ui.upload");
/// Uploading dirty pixels to the GPU.
pub static UI_UPLOAD: Histogram = Histogram::new("ui.upload", 10);
/// Building and presenting one window frame (egui + wgpu + present).
pub static UI_RENDER: Histogram = Histogram::new("ui.render", 33);

/// Audio packets received from the server.
pub static AUDIO_PACKETS: Counter = Counter::count("audio.packets");
/// Decoding one audio packet.
pub static AUDIO_DECODE: Histogram = Histogram::new("audio.decode", 10);
/// Playback buffer depth when a packet arrives (latency the user hears).
pub static AUDIO_BUFFER: Histogram = Histogram::new("audio.buffer", 400);
/// Samples dropped to stay in sync or because the queue was full.
pub static AUDIO_DROPPED: Counter = Counter::count("audio.dropped_samples");
/// Microphone packets sent.
pub static MIC_PACKETS: Counter = Counter::count("mic.packets");

/// Webcam frames sent.
pub static CAMERA_FRAMES: Counter = Counter::count("camera.frames");
/// Webcam bytes sent.
pub static CAMERA_TX: Counter = Counter::bytes("camera.tx");

/// Clipboard payload bytes transferred (both directions).
pub static CLIPBOARD_BYTES: Counter = Counter::bytes("clipboard");

static COUNTERS: &[&Counter] = &[
    &NET_RX,
    &NET_TX,
    &NET_PDUS,
    &FRAME_UPDATES,
    &FRAME_PIXELS,
    &VIDEO_FRAMES,
    &VIDEO_HW_FALLBACKS,
    &INPUT_BATCHES,
    &UI_FRAMES,
    &UI_UPLOAD_BYTES,
    &AUDIO_PACKETS,
    &AUDIO_DROPPED,
    &MIC_PACKETS,
    &CAMERA_FRAMES,
    &CAMERA_TX,
    &CLIPBOARD_BYTES,
];

static HISTOGRAMS: &[&Histogram] = &[
    &NET_WRITE,
    &RDP_PROCESS,
    &FRAME_PUBLISH,
    &FRAME_LATENCY,
    &VIDEO_DECODE,
    &VIDEO_CONVERT,
    &INPUT_QUEUE,
    &INPUT_LATENCY,
    &UI_EVENT,
    &UI_UPLOAD,
    &UI_RENDER,
    &AUDIO_DECODE,
    &AUDIO_BUFFER,
];

// --- Reporting ---------------------------------------------------------------------------------

struct HistSnapshot {
    count: u64,
    sum_us: u64,
    max_us: u64,
    slow: u64,
    buckets: [u64; BUCKETS],
}

impl HistSnapshot {
    /// Upper bound of the bucket containing the `p` quantile, capped at the exact max.
    fn percentile_us(&self, p: f64) -> u64 {
        let total: u64 = self.buckets.iter().sum();
        if total == 0 {
            return 0;
        }
        let rank = ((p * total as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += n;
            if seen >= rank {
                let upper = if i == 0 { 0 } else { (1u64 << i) - 1 };
                return upper.min(self.max_us);
            }
        }
        self.max_us
    }
}

/// One interval's summary.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub line: String,
    /// Timings that crossed their slow threshold, e.g. `rdp.process max=45.2ms (3× ≥30ms)`.
    pub slow: Vec<String>,
}

fn ms(us: u64) -> String {
    let v = us as f64 / 1000.0;
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    }
}

fn bytes(n: f64) -> String {
    match n {
        n if n >= 1e9 => format!("{:.2}GB", n / 1e9),
        n if n >= 1e6 => format!("{:.1}MB", n / 1e6),
        n if n >= 1e3 => format!("{:.1}kB", n / 1e3),
        n => format!("{n:.0}B"),
    }
}

/// Takes (and resets) everything recorded since the last call. `None` when nothing happened.
pub fn collect(elapsed: Duration) -> Option<Report> {
    let secs = elapsed.as_secs_f64().max(0.001);
    let mut line = String::new();
    let mut slow = Vec::new();
    for c in COUNTERS {
        let v = c.take();
        if v == 0 {
            continue;
        }
        let rate = v as f64 / secs;
        let _ = match c.unit {
            Unit::Bytes => write!(line, "{}={} ({}/s) ", c.name, bytes(v as f64), bytes(rate)),
            Unit::Count => write!(line, "{}={v} ({rate:.0}/s) ", c.name),
        };
    }
    for h in HISTOGRAMS {
        let s = h.take();
        if s.count == 0 {
            continue;
        }
        let _ = write!(
            line,
            "{}[n={} avg={} p50={} p95={} p99={} max={}]ms ",
            h.name,
            s.count,
            ms(s.sum_us / s.count),
            ms(s.percentile_us(0.50)),
            ms(s.percentile_us(0.95)),
            ms(s.percentile_us(0.99)),
            ms(s.max_us),
        );
        if s.slow > 0 {
            slow.push(format!("{} max={}ms ({}× ≥{}ms)", h.name, ms(s.max_us), s.slow, h.slow_us / 1000));
        }
    }
    if line.is_empty() {
        return None;
    }
    line.truncate(line.trim_end().len());
    Some(Report { line, slow })
}

/// Reporter interval from `BASTION_METRICS` (`off`/`0` disables; default 10 s).
pub fn interval_from_env() -> Option<Duration> {
    parse_interval(std::env::var("BASTION_METRICS").ok().as_deref())
}

fn parse_interval(v: Option<&str>) -> Option<Duration> {
    match v.map(str::trim) {
        None | Some("") | Some("on") => Some(Duration::from_secs(10)),
        Some("0" | "off" | "false" | "no") => None,
        Some(s) => Some(Duration::from_secs(s.parse::<u64>().unwrap_or(10).clamp(1, 3600))),
    }
}

/// Starts the background reporter thread (one summary line per `interval`, nothing when idle).
pub fn start_reporter(interval: Duration) {
    tracing::info!(interval_secs = interval.as_secs(), "Performance metrics enabled");
    let spawned = std::thread::Builder::new().name("bastion-metrics".into()).spawn(move || {
        let mut last = Instant::now();
        // Drop whatever accumulated before the reporter started.
        let _ = collect(interval);
        loop {
            std::thread::sleep(interval);
            let now = Instant::now();
            if let Some(r) = collect(now - last) {
                if r.slow.is_empty() {
                    tracing::info!(target: "bastion::metrics", "{}", r.line);
                } else {
                    tracing::warn!(target: "bastion::metrics", slow = %r.slow.join("; "), "{}", r.line);
                }
            }
            last = now;
        }
    });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "Cannot start the metrics reporter");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The metrics are process-wide statics; tests use a private histogram where possible and
    // serialise the ones that go through `collect`.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn buckets_are_powers_of_two() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1), 1);
        assert_eq!(bucket(2), 2);
        assert_eq!(bucket(3), 2);
        assert_eq!(bucket(1024), 11);
        assert_eq!(bucket(u64::MAX), BUCKETS - 1);
    }

    #[test]
    fn histogram_summarises_and_resets() {
        let h = Histogram::new("t", 5);
        for us in [100, 200, 300, 400, 10_000] {
            h.record_us(us);
        }
        let s = h.take();
        assert_eq!((s.count, s.sum_us, s.max_us, s.slow), (5, 11_000, 10_000, 1));
        assert!(s.percentile_us(0.5) >= 300 && s.percentile_us(0.5) < 600, "{}", s.percentile_us(0.5));
        assert_eq!(s.percentile_us(0.99), 10_000, "capped at the exact max");
        assert_eq!(h.take().count, 0);
    }

    #[test]
    fn stamp_measures_the_oldest_pending_item() {
        let s = Stamp::default();
        assert_eq!(s.take(), None);
        s.mark();
        std::thread::sleep(Duration::from_millis(5));
        s.mark(); // newer mark doesn't reset the older one
        assert!(s.take().unwrap() >= Duration::from_millis(5));
        assert_eq!(s.take(), None);
    }

    #[test]
    fn idle_interval_produces_no_line() {
        let _g = SERIAL.lock().unwrap();
        let _ = collect(Duration::from_secs(1));
        assert_eq!(collect(Duration::from_secs(1)), None);
    }

    #[test]
    fn report_has_rates_percentiles_and_slow_callouts() {
        let _g = SERIAL.lock().unwrap();
        let _ = collect(Duration::from_secs(1));
        NET_RX.add(2_000_000);
        RDP_PROCESS.record(Duration::from_millis(1));
        RDP_PROCESS.record(Duration::from_millis(45));
        let r = collect(Duration::from_secs(2)).unwrap();
        assert!(r.line.contains("net.rx=2.0MB (1.0MB/s)"), "{}", r.line);
        assert!(r.line.contains("rdp.process[n=2 avg=23.0"), "{}", r.line);
        assert_eq!(r.slow, vec!["rdp.process max=45.0ms (1× ≥30ms)".to_owned()]);
    }

    #[test]
    fn interval_parsing() {
        assert_eq!(parse_interval(None), Some(Duration::from_secs(10)));
        assert_eq!(parse_interval(Some("off")), None);
        assert_eq!(parse_interval(Some("0")), None);
        assert_eq!(parse_interval(Some("30")), Some(Duration::from_secs(30)));
        assert_eq!(parse_interval(Some("junk")), Some(Duration::from_secs(10)));
    }
}
