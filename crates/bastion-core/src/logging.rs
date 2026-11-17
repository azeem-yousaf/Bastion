//! Logging: daily-rotated files in `~/.local/state/bastion/logs` plus stderr.
//!
//! Redaction policy: code never logs secrets or keystrokes. As defence in depth, the
//! file layer runs every line through [`redact`] which masks `password=`/`pass:`-style
//! values that might slip in via third-party crates' debug output.

use std::io::Write;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

use crate::paths::{AppPaths, ensure_private_dir};

/// Keep the returned guard alive for the life of the process (flushes on drop).
pub struct LogGuard {
    _file: tracing_appender::non_blocking::WorkerGuard,
}

const SENSITIVE_KEYS: &[&str] = &["password", "passwd", "pass", "pin", "secret", "gw_pass", "token"];

/// Masks values following sensitive keys in a log line (`key: value`, `key=value`, `key: "value"`).
pub fn redact(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        let mut matched = None;
        for key in SENSITIVE_KEYS {
            if lower[i..].starts_with(key) {
                let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                let after = i + key.len();
                let rest = &line[after..];
                let sep_len = rest.len() - rest.trim_start_matches([' ', ':', '=']).len();
                if prev_ok && sep_len > 0 && rest[..sep_len].contains([':', '=']) {
                    matched = Some(after + sep_len);
                    break;
                }
            }
        }
        match matched {
            Some(value_start) => {
                out.push_str(&line[i..value_start]);
                let rest = &line[value_start..];
                let (quoted, body) = match rest.strip_prefix('"') {
                    Some(b) => (true, b),
                    None => (false, rest),
                };
                let end = if quoted {
                    body.find('"').map_or(body.len(), |e| e + 1)
                } else {
                    body.find([' ', ',', '}', ')', '\n']).unwrap_or(body.len())
                };
                out.push_str("<redacted>");
                i = value_start + usize::from(quoted) + end;
            }
            None => {
                let ch = line[i..].chars().next().unwrap_or(' ');
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

struct RedactingWriter<W: Write> {
    inner: W,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.inner.write_all(redact(&text).as_bytes())?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Initialises global logging. `level` is an EnvFilter directive (e.g. "info", "bastion=debug").
pub fn init(paths: &AppPaths, level: &str) -> Result<LogGuard> {
    let dir = paths.log_dir();
    ensure_private_dir(&dir)?;
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("bastion")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir)?;
    let (file_writer, guard) = tracing_appender::non_blocking(RedactingWriter { inner: appender });

    // Noisy protocol crates are capped at `warn` unless explicitly requested.
    let directive = std::env::var("BASTION_LOG").unwrap_or_else(|_| {
        format!("{level},sspi=warn,ironrdp_tls=warn,wgpu_core=warn,wgpu_hal=warn,naga=warn,zbus=warn")
    });
    let filter = EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(file_writer).with_ansi(false).with_target(true))
        .with(fmt::layer().with_writer(|| RedactingWriter { inner: std::io::stderr() }).with_target(false))
        .try_init()
        .ok();

    Ok(LogGuard { _file: guard })
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn masks_values() {
        assert_eq!(redact("gw_pass: \"abc def\", x: 1"), "gw_pass: <redacted>, x: 1");
        assert_eq!(redact("password=hunter2 next"), "password=<redacted> next");
        assert_eq!(redact("compass: north"), "compass: north");
        assert_eq!(redact("no secrets here"), "no secrets here");
    }
}
