//! Logging: daily-rotated files in `~/.local/state/bastion/logs` plus stderr.
//!
//! Retention: the current day's file stays plain text; earlier days are gzip-compressed, and
//! anything older than [`RETENTION_DAYS`] is deleted. A background thread does this at startup
//! and hourly (Bastion often runs for days in the tray). Dates are UTC, as in the file names.
//!
//! Redaction policy: code never logs secrets or keystrokes. As defence in depth, the
//! file layer runs every line through [`redact`] which masks `password=`/`pass:`-style
//! values that might slip in via third-party crates' debug output.

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

use crate::paths::{AppPaths, ensure_private_dir};

/// Keep the returned guard alive for the life of the process (flushes on drop).
pub struct LogGuard {
    _file: tracing_appender::non_blocking::WorkerGuard,
    _stderr: tracing_appender::non_blocking::WorkerGuard,
}

/// Days of logs kept, including today (older files are deleted).
pub const RETENTION_DAYS: i64 = 7;
const LOG_PREFIX: &str = "bastion.";

/// What one maintenance pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Maintenance {
    pub compressed: usize,
    pub deleted: usize,
}

/// Date of a `bastion.YYYY-MM-DD.log[.gz]` file, and whether it is already compressed.
fn log_file_date(name: &str) -> Option<(time::Date, bool)> {
    let rest = name.strip_prefix(LOG_PREFIX)?;
    let (date, gz) = match rest.strip_suffix(".log.gz") {
        Some(d) => (d, true),
        None => (rest.strip_suffix(".log")?, false),
    };
    let mut it = date.splitn(3, '-');
    let (y, m, d) = (it.next()?.parse().ok()?, it.next()?.parse::<u8>().ok()?, it.next()?.parse().ok()?);
    Some((time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?, gz))
}

/// Compresses earlier days' logs and deletes logs older than [`RETENTION_DAYS`].
/// Files that don't look like Bastion logs are left alone.
pub fn maintain_logs(dir: &Path, today: time::Date) -> std::io::Result<Maintenance> {
    let mut done = Maintenance::default();
    let oldest_kept = today - time::Duration::days(RETENTION_DAYS - 1);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|n| n.starts_with(LOG_PREFIX) && n.ends_with(".log.gz.tmp")) {
            // Left by an interrupted compression; the original log is still there.
            std::fs::remove_file(entry.path())?;
            continue;
        }
        let Some((date, gz)) = name.to_str().and_then(log_file_date) else { continue };
        let path = entry.path();
        if date < oldest_kept {
            std::fs::remove_file(&path)?;
            done.deleted += 1;
        } else if !gz && date < today {
            compress(&path)?;
            done.compressed += 1;
        }
    }
    Ok(done)
}

/// `x.log` → `x.log.gz` (written to a temporary name first, so a crash never leaves a
/// half-written archive in place of the log), then removes the original.
fn compress(path: &Path) -> std::io::Result<()> {
    let mut gz_name = path.as_os_str().to_owned();
    gz_name.push(".gz");
    let gz_path = std::path::PathBuf::from(gz_name);
    let tmp = gz_path.with_extension("gz.tmp");
    {
        let mut input = std::io::BufReader::new(std::fs::File::open(path)?);
        let out = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode_private().open(&tmp)?;
        let mut enc = flate2::write::GzEncoder::new(std::io::BufWriter::new(out), flate2::Compression::default());
        std::io::copy(&mut input, &mut enc)?;
        enc.finish()?.into_inner().map_err(std::io::IntoInnerError::into_error)?.sync_all()?;
    }
    std::fs::rename(&tmp, &gz_path)?;
    std::fs::remove_file(path)
}

trait PrivateMode {
    fn mode_private(&mut self) -> &mut Self;
}

impl PrivateMode for std::fs::OpenOptions {
    /// Logs may contain host names and user names: owner-only, like the log directory.
    fn mode_private(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.mode(0o600)
    }
}

fn start_log_maintenance(dir: std::path::PathBuf) {
    let spawned = std::thread::Builder::new().name("bastion-logmaint".into()).spawn(move || {
        loop {
            match maintain_logs(&dir, time::OffsetDateTime::now_utc().date()) {
                Ok(m) if m != Maintenance::default() => {
                    tracing::info!(compressed = m.compressed, deleted = m.deleted, "Old logs tidied");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Could not tidy old logs"),
            }
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "Cannot start log maintenance");
    }
}

/// Lines queued for the log thread before new ones are dropped (never blocks the caller).
const LOG_QUEUE_LINES: usize = 16_384;
/// Size of the batch written to disk per flush.
const LOG_WRITE_BUFFER: usize = 64 * 1024;

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
    // Off the calling thread (non_blocking, lossy rather than ever blocking a hot path), and
    // batched: the background worker drains every queued line and then flushes once, so the
    // buffer turns a burst of lines into a single write() instead of one per line.
    let (file_writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(LOG_QUEUE_LINES)
        .thread_name("bastion-log")
        .finish(RedactingWriter { inner: std::io::BufWriter::with_capacity(LOG_WRITE_BUFFER, appender) });
    let (stderr_writer, stderr_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .thread_name("bastion-stderr")
        .finish(RedactingWriter { inner: std::io::stderr() });

    // Noisy protocol crates are capped at `warn` unless explicitly requested.
    let directive = std::env::var("BASTION_LOG").unwrap_or_else(|_| {
        format!("{level},sspi=warn,ironrdp_tls=warn,wgpu_core=warn,wgpu_hal=warn,naga=warn,zbus=warn")
    });
    let filter = EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(file_writer).with_ansi(false).with_target(true))
        .with(fmt::layer().with_writer(stderr_writer).with_target(false))
        .try_init()
        .ok();

    start_log_maintenance(dir);
    Ok(LogGuard { _file: guard, _stderr: stderr_guard })
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn old_days_are_compressed_and_expired_logs_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let today = time::macros::date!(2026 - 11 - 17);
        let write = |name: &str, body: &str| std::fs::write(dir.path().join(name), body).unwrap();
        write("bastion.2026-11-17.log", "today");
        write("bastion.2026-11-16.log", "yesterday\n".repeat(1000).as_str());
        write("bastion.2026-11-11.log", "six days ago"); // last day kept
        write("bastion.2026-11-10.log", "seven days ago");
        write("bastion.2026-11-01.log.gz", "old archive");
        write("notes.txt", "not ours");
        write("bastion.2026-11-15.log.gz.tmp", "interrupted");

        let m = maintain_logs(dir.path(), today).unwrap();
        assert_eq!(m, Maintenance { compressed: 2, deleted: 2 });

        let mut names: Vec<String> =
            std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(
            names,
            ["bastion.2026-11-11.log.gz", "bastion.2026-11-16.log.gz", "bastion.2026-11-17.log", "notes.txt"]
        );
        let gz = dir.path().join("bastion.2026-11-16.log.gz");
        let mut text = String::new();
        flate2::read::GzDecoder::new(std::fs::File::open(&gz).unwrap()).read_to_string(&mut text).unwrap();
        assert_eq!(text, "yesterday\n".repeat(1000), "compression round-trips");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&gz).unwrap().permissions().mode() & 0o777, 0o600);

        // Idempotent: a second pass has nothing to do.
        assert_eq!(maintain_logs(dir.path(), today).unwrap(), Maintenance::default());
    }

    #[test]
    fn parses_only_bastion_log_names() {
        assert_eq!(log_file_date("bastion.2026-11-16.log"), Some((time::macros::date!(2026 - 11 - 16), false)));
        assert_eq!(log_file_date("bastion.2026-11-16.log.gz"), Some((time::macros::date!(2026 - 11 - 16), true)));
        assert_eq!(log_file_date("bastion.2026-13-16.log"), None);
        assert_eq!(log_file_date("bastion.2026-11-16.log.gz.tmp"), None);
        assert_eq!(log_file_date("other.2026-11-16.log"), None);
    }

    #[test]
    fn masks_values() {
        assert_eq!(redact("gw_pass: \"abc def\", x: 1"), "gw_pass: <redacted>, x: 1");
        assert_eq!(redact("password=hunter2 next"), "password=<redacted> next");
        assert_eq!(redact("compass: north"), "compass: north");
        assert_eq!(redact("no secrets here"), "no secrets here");
    }
}
