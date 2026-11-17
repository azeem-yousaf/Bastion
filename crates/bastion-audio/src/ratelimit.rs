//! Rate limiting for log lines whose frequency a remote server controls.
//!
//! A server decides how often it sends Formats/Open/FormatChange/Wave PDUs, so a line logged
//! once per such PDU lets it write to the log file as fast as it can send. Each call site gets a
//! [`LogGate`] that lets a short burst through per window; the rest are only counted
//! (`log.suppressed` in the metrics line).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Lines let through per window, per call site.
const BURST: u64 = 5;
/// Window length in seconds.
const WINDOW_SECS: u64 = 30;

/// Lock-free "at most [`BURST`] per [`WINDOW_SECS`]" gate. One `static` per call site.
pub(crate) struct LogGate {
    /// Window number (upper 32 bits, 0 = never used) and lines let through in it (lower 32 bits).
    state: AtomicU64,
}

impl LogGate {
    pub(crate) const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    /// Whether the caller may log now.
    pub(crate) fn allow(&self) -> bool {
        static START: OnceLock<Instant> = OnceLock::new();
        let window = START.get_or_init(Instant::now).elapsed().as_secs() / WINDOW_SECS + 1;
        let allowed = self.allow_in(window);
        if !allowed {
            bastion_metrics::LOG_SUPPRESSED.incr();
        }
        allowed
    }

    fn allow_in(&self, window: u64) -> bool {
        let window = window & 0xFFFF_FFFF;
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let next = if current >> 32 != window {
                (window << 32) | 1
            } else if current & 0xFFFF_FFFF < BURST {
                current + 1
            } else {
                return false;
            };
            match self.state.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
    }
}

/// `gated!(warn, ...)`: like `tracing::warn!(...)` but rate-limited per call site. The arguments
/// are only evaluated when the line is actually logged.
macro_rules! gated {
    ($level:ident, $($arg:tt)+) => {{
        static GATE: $crate::ratelimit::LogGate = $crate::ratelimit::LogGate::new();
        if GATE.allow() {
            ::tracing::$level!($($arg)+);
        }
    }};
}
pub(crate) use gated;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lets_a_burst_through_per_window_then_suppresses() {
        let gate = LogGate::new();
        assert_eq!((0..1000).filter(|_| gate.allow_in(1)).count() as u64, BURST);
        // A new window starts a new burst; an old window number does too (clock is monotonic,
        // so this only means "different").
        assert_eq!((0..1000).filter(|_| gate.allow_in(2)).count() as u64, BURST);
        assert!(!gate.allow_in(2));
    }

    #[test]
    fn concurrent_callers_share_one_budget() {
        let gate = LogGate::new();
        let allowed: u64 = std::thread::scope(|s| {
            let handles: Vec<_> =
                (0..8).map(|_| s.spawn(|| (0..500).filter(|_| gate.allow_in(7)).count() as u64)).collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(allowed, BURST);
    }
}
