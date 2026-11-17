#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

/// EGFX dynamic virtual channel name per MS-RDPEGFX
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// Bastion patch: `tracing::warn!` for conditions the peer can trigger once per PDU (or per
/// rectangle). A graphics message expands to as much as 256 MiB of PDUs, so an unconditional
/// warning lets a few bytes on the wire write millions of log lines. Each call site logs its
/// 1st, 2nd, 4th, 8th, ... occurrence, with the running count.
macro_rules! warn_throttled {
    ($($arg:tt)+) => {{
        static OCCURRENCES: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(0);
        if let Some(occurrences) = $crate::throttled_occurrence(&OCCURRENCES) {
            ::tracing::warn!(occurrences, $($arg)+);
        }
    }};
}

/// Counts one occurrence at a [`warn_throttled`] call site; `Some(count)` when it is one to log.
#[doc(hidden)]
pub fn throttled_occurrence(occurrences: &core::sync::atomic::AtomicU64) -> Option<u64> {
    let count = occurrences
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .wrapping_add(1);
    count.is_power_of_two().then_some(count)
}

#[cfg(test)]
mod throttle_tests {
    /// Bastion patch: a call site reached ten million times (one decompressed message of
    /// minimal PDUs) logs 24 lines, not ten million.
    #[test]
    fn a_call_site_logs_logarithmically_often() {
        let occurrences = core::sync::atomic::AtomicU64::new(0);
        let logged: Vec<u64> = (0..10_000_000u32)
            .filter_map(|_| super::throttled_occurrence(&occurrences))
            .collect();
        assert_eq!(logged.len(), 24);
        assert_eq!(logged[..4], [1, 2, 4, 8]);
    }
}

pub mod avc444;
pub mod cache;
pub mod client;
pub mod compositor;
pub mod decode;
pub mod encode;
pub mod pdu;
pub mod server;
