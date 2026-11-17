//! Connection quality indicator: turns the engine's raw link samples (see
//! `bastion_session::link`) into the latency, loss, frame rate and bandwidth shown in the session
//! bar, a Good / Fair / Poor rating, and a one-off warning when the connection stays poor.
//!
//! Pure logic (no UI, no clock of its own) so it is unit-tested.

use std::time::{Duration, Instant};

use bastion_session::LinkSample;

/// How often the UI samples the link.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// A remote computer's measurement older than this is no longer shown.
const SERVER_REPORT_MAX_AGE: Duration = Duration::from_secs(120);
/// Loss is only computed over windows with at least this many segments sent (fewer is noise).
const MIN_SEGMENTS_FOR_LOSS: u32 = 50;
/// Consecutive poor samples before warning, and good samples before warning again.
const POOR_SAMPLES_TO_WARN: u32 = 5;
const GOOD_SAMPLES_TO_REARM: u32 = 30;
/// Never warn more often than this.
const WARN_COOLDOWN: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Good,
    Fair,
    Poor,
    /// No latency measurement yet.
    Unknown,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Good => "Good",
            Level::Fair => "Fair",
            Level::Poor => "Poor",
            Level::Unknown => "Measuring…",
        }
    }
}

/// Where the latency figure comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencySource {
    /// The TCP connection to the remote computer (kernel round-trip time).
    Direct,
    /// The TCP connection to the RD Gateway (the gateway → computer leg is not included).
    Gateway,
    /// Measured by the remote computer (network auto-detect).
    RemotePc,
}

impl LatencySource {
    pub fn describe(self) -> &'static str {
        match self {
            LatencySource::Direct => "Round trip to the remote computer",
            LatencySource::Gateway => "Round trip to the RD Gateway",
            LatencySource::RemotePc => "Round trip measured by the remote computer",
        }
    }
}

/// What the indicator shows.
#[derive(Debug, Clone, PartialEq)]
pub struct Quality {
    pub level: Level,
    pub latency_ms: Option<f32>,
    pub latency_source: Option<LatencySource>,
    pub jitter_ms: Option<f32>,
    /// Share of TCP segments retransmitted over the last interval, in percent.
    pub loss_pct: Option<f32>,
    pub fps: f32,
    pub down_mbps: f32,
    pub up_mbps: f32,
    /// The remote computer's estimate of the available bandwidth.
    pub capacity_mbps: Option<f32>,
    pub via_gateway: bool,
}

impl Quality {
    /// Short text next to the coloured dot in the session bar.
    pub fn chip_text(&self) -> String {
        match self.latency_ms {
            Some(ms) => format!("{} ms", format_ms(ms)),
            None => "— ms".into(),
        }
    }
}

pub fn format_ms(ms: f32) -> String {
    if ms < 1.0 { "<1".into() } else { format!("{ms:.0}") }
}

/// Rates a connection: latency drives it, packet loss can only make it worse.
pub fn level(latency_ms: Option<f32>, loss_pct: Option<f32>) -> Level {
    let loss = loss_pct.unwrap_or(0.0);
    let Some(ms) = latency_ms else {
        return if loss >= 5.0 { Level::Poor } else { Level::Unknown };
    };
    if ms >= 150.0 || loss >= 5.0 {
        Level::Poor
    } else if ms >= 50.0 || loss >= 1.0 {
        Level::Fair
    } else {
        Level::Good
    }
}

/// Picks the most meaningful latency figure for the connection.
fn latency(now: Instant, s: &LinkSample) -> Option<(f32, LatencySource)> {
    let server = s
        .server
        .filter(|r| now.saturating_duration_since(r.at) <= SERVER_REPORT_MAX_AGE)
        .map(|r| (r.average_rtt_ms as f32, LatencySource::RemotePc));
    let tcp = s.tcp.map(|t| {
        let ms = t.rtt.as_secs_f32() * 1000.0;
        (ms, if s.via_gateway { LatencySource::Gateway } else { LatencySource::Direct })
    });
    // Direct: the kernel's figure is end to end and always current. Through a gateway it covers
    // only the first leg, so the remote computer's own measurement wins when there is one.
    if s.via_gateway { server.or(tcp) } else { tcp.or(server) }
}

/// Keeps the previous sample to compute rates, and decides when to warn.
#[derive(Debug, Default)]
pub struct Meter {
    prev: Option<(Instant, LinkSample)>,
    pub current: Option<Quality>,
    poor_streak: u32,
    good_streak: u32,
    armed_since_warning: bool,
    last_warning: Option<Instant>,
}

/// Result of one sample.
#[derive(Debug, Default, PartialEq)]
pub struct Update {
    /// The displayed figures changed (repaint if the indicator is visible).
    pub changed: bool,
    /// Show this warning to the user.
    pub warning: Option<String>,
}

impl Meter {
    /// Forgets the previous connection (after a reconnect).
    pub fn reset(&mut self) {
        let last_warning = self.last_warning;
        *self = Self { last_warning, ..Self::default() };
    }

    pub fn update(&mut self, now: Instant, sample: LinkSample) -> Update {
        let Some((then, prev)) = self.prev.replace((now, sample)) else {
            return Update::default();
        };
        let secs = now.saturating_duration_since(then).as_secs_f32();
        if secs <= 0.0 {
            return Update::default();
        }
        let rate = |a: u64, b: u64| a.saturating_sub(b) as f32 / secs;
        let loss_pct = match (sample.tcp, prev.tcp) {
            (Some(t), Some(p)) if t.segs_out.wrapping_sub(p.segs_out) >= MIN_SEGMENTS_FOR_LOSS => {
                let sent = t.segs_out.wrapping_sub(p.segs_out) as f32;
                Some((t.retransmits.saturating_sub(p.retransmits) as f32 / sent * 100.0).min(100.0))
            }
            _ => None,
        };
        let lat = latency(now, &sample);
        let q = Quality {
            level: level(lat.map(|l| l.0), loss_pct),
            latency_ms: lat.map(|l| l.0),
            latency_source: lat.map(|l| l.1),
            jitter_ms: sample
                .tcp
                .filter(|_| lat.is_some_and(|l| l.1 != LatencySource::RemotePc))
                .map(|t| t.rtt_var.as_secs_f32() * 1000.0),
            loss_pct,
            fps: rate(sample.frames, prev.frames),
            down_mbps: rate(sample.rx_bytes, prev.rx_bytes) * 8.0 / 1e6,
            up_mbps: rate(sample.tx_bytes, prev.tx_bytes) * 8.0 / 1e6,
            capacity_mbps: sample
                .server
                .filter(|r| now.saturating_duration_since(r.at) <= SERVER_REPORT_MAX_AGE)
                .and_then(|r| r.bandwidth_kbps)
                .map(|k| k as f32 / 1000.0),
            via_gateway: sample.via_gateway,
        };

        let mut warning = None;
        if q.level == Level::Poor {
            self.poor_streak += 1;
            self.good_streak = 0;
            let cooled = self.last_warning.is_none_or(|t| now.saturating_duration_since(t) >= WARN_COOLDOWN);
            if self.poor_streak == POOR_SAMPLES_TO_WARN && !self.armed_since_warning && cooled {
                self.armed_since_warning = true;
                self.last_warning = Some(now);
                warning = Some(warning_text(&q));
            }
        } else {
            self.poor_streak = 0;
            if q.level != Level::Unknown {
                self.good_streak += 1;
                if self.good_streak >= GOOD_SAMPLES_TO_REARM {
                    self.armed_since_warning = false;
                }
            }
        }
        let changed = self.current.as_ref() != Some(&q);
        self.current = Some(q);
        Update { changed, warning }
    }
}

fn warning_text(q: &Quality) -> String {
    let mut why = Vec::new();
    if let Some(ms) = q.latency_ms.filter(|ms| *ms >= 150.0) {
        why.push(format!("{} ms latency", format_ms(ms)));
    }
    if let Some(l) = q.loss_pct.filter(|l| *l >= 5.0) {
        why.push(format!("{l:.0} % packet loss"));
    }
    if why.is_empty() {
        "The connection is poor; the remote desktop may feel slow.".into()
    } else {
        format!("The connection is poor ({}); the remote desktop may feel slow.", why.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use bastion_session::{ServerReport, TcpSample};

    use super::*;

    fn tcp(rtt_ms: u64, segs: u32, retrans: u32) -> Option<TcpSample> {
        Some(TcpSample {
            rtt: Duration::from_millis(rtt_ms),
            rtt_var: Duration::from_millis(rtt_ms / 4),
            segs_out: segs,
            retransmits: retrans,
        })
    }

    fn sample(rx: u64, frames: u64, tcp: Option<TcpSample>) -> LinkSample {
        LinkSample { rx_bytes: rx, tx_bytes: rx / 100, frames, tcp, server: None, via_gateway: false }
    }

    #[test]
    fn ratings_follow_latency_and_loss() {
        assert_eq!(level(Some(0.4), None), Level::Good);
        assert_eq!(level(Some(49.0), Some(0.5)), Level::Good);
        assert_eq!(level(Some(50.0), None), Level::Fair);
        assert_eq!(level(Some(10.0), Some(2.0)), Level::Fair);
        assert_eq!(level(Some(150.0), None), Level::Poor);
        assert_eq!(level(Some(10.0), Some(8.0)), Level::Poor);
        assert_eq!(level(None, None), Level::Unknown);
        assert_eq!(level(None, Some(10.0)), Level::Poor);
    }

    #[test]
    fn rates_come_from_two_samples() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        assert_eq!(m.update(t0, sample(0, 0, tcp(20, 0, 0))), Update::default());
        let u = m.update(t0 + Duration::from_secs(2), sample(2_500_000, 60, tcp(20, 200, 2)));
        assert!(u.changed);
        let q = m.current.unwrap();
        assert_eq!(q.fps, 30.0);
        assert_eq!(q.down_mbps, 10.0); // 2.5 MB over 2 s
        assert_eq!(q.latency_ms, Some(20.0));
        assert_eq!(q.latency_source, Some(LatencySource::Direct));
        assert_eq!(q.loss_pct, Some(1.0));
        assert_eq!(q.level, Level::Fair); // 1 % loss
        assert_eq!(q.chip_text(), "20 ms");
    }

    #[test]
    fn loss_needs_enough_traffic() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        m.update(t0, sample(0, 0, tcp(5, 100, 0)));
        m.update(t0 + SAMPLE_INTERVAL, sample(0, 0, tcp(5, 110, 3)));
        assert_eq!(m.current.unwrap().loss_pct, None);
    }

    #[test]
    fn gateway_prefers_the_remote_computers_measurement() {
        let now = Instant::now();
        let report = ServerReport { at: now, average_rtt_ms: 80, base_rtt_ms: None, bandwidth_kbps: Some(50_000) };
        let mut s = sample(0, 0, tcp(3, 0, 0));
        s.via_gateway = true;
        assert_eq!(latency(now, &s), Some((3.0, LatencySource::Gateway)));
        s.server = Some(report);
        assert_eq!(latency(now, &s), Some((80.0, LatencySource::RemotePc)));
        // Stale reports are ignored.
        assert_eq!(latency(now + Duration::from_secs(600), &s), Some((3.0, LatencySource::Gateway)));
        // Direct connections keep the live kernel figure.
        s.via_gateway = false;
        assert_eq!(latency(now, &s), Some((3.0, LatencySource::Direct)));
        s.tcp = None;
        assert_eq!(latency(now, &s), Some((80.0, LatencySource::RemotePc)));
    }

    #[test]
    fn warns_once_when_the_connection_stays_poor() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        let at = |i: u64| t0 + Duration::from_secs(i);
        let mut warnings = Vec::new();
        for i in 0..20 {
            if let Some(w) = m.update(at(i), sample(0, 0, tcp(300, 0, 0))).warning {
                warnings.push((i, w));
            }
        }
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0].0, POOR_SAMPLES_TO_WARN as u64);
        assert!(warnings[0].1.contains("300 ms latency"), "{}", warnings[0].1);
    }

    #[test]
    fn a_brief_spike_does_not_warn() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        for i in 0..40u64 {
            let rtt = if i % 4 == 0 { 400 } else { 10 };
            assert_eq!(m.update(t0 + Duration::from_secs(i), sample(0, 0, tcp(rtt, 0, 0))).warning, None);
        }
    }

    #[test]
    fn warns_again_only_after_recovering_and_a_cooldown() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        let mut t = 0u64;
        let mut run = |m: &mut Meter, rtt: u64, n: u64| {
            let mut count = 0;
            for _ in 0..n {
                t += 1;
                count +=
                    usize::from(m.update(t0 + Duration::from_secs(t), sample(0, 0, tcp(rtt, 0, 0))).warning.is_some());
            }
            count
        };
        assert_eq!(run(&mut m, 300, 10), 1);
        // Recovered but within the cooldown: poor again does not warn.
        assert_eq!(run(&mut m, 10, 40), 0);
        assert_eq!(run(&mut m, 300, 10), 0);
        // Long enough later, after recovering: warns again.
        assert_eq!(run(&mut m, 10, 300), 0);
        assert_eq!(run(&mut m, 300, 10), 1);
    }

    #[test]
    fn reset_keeps_the_warning_cooldown() {
        let mut m = Meter::default();
        let t0 = Instant::now();
        for i in 0..10 {
            m.update(t0 + Duration::from_secs(i), sample(0, 0, tcp(300, 0, 0)));
        }
        m.reset();
        assert!(m.current.is_none());
        let warned = (10..30)
            .filter(|&i| m.update(t0 + Duration::from_secs(i), sample(0, 0, tcp(300, 0, 0))).warning.is_some())
            .count();
        assert_eq!(warned, 0);
    }
}
