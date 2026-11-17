//! Logging: daily-rotated files in `~/.local/state/bastion/logs` plus stderr.
//!
//! Retention: the current day's file stays plain text; earlier days are gzip-compressed, and
//! anything older than [`RETENTION_DAYS`] is deleted. A background thread does this at startup
//! and hourly (Bastion often runs for days in the tray). Dates are UTC, as in the file names.
//!
//! Redaction policy: code never logs secrets or keystrokes. As defence in depth, the
//! file layer runs every line through [`redact`] which masks `password=`/`pass:`-style
//! values that might slip in via third-party crates' debug output.
//!
//! Some dependencies log credential material when asked for debug/trace output (see
//! [`CREDENTIAL_CAPS`]). Those targets are capped by [`credential_cap_allows`] whatever
//! `BASTION_LOG` or the settings say; there is deliberately no way to lift the caps.
//!
//! Log files are created 0600 inside the 0700 log directory.

use std::io::Write;
use std::path::Path;

use anyhow::{Context as _, Result};
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
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

/// `bastion.YYYY-MM-DD.log`, the name [`log_file_date`] parses.
fn log_file_name(date: time::Date) -> String {
    format!("{LOG_PREFIX}{:04}-{:02}-{:02}.log", date.year(), u8::from(date.month()), date.day())
}

/// Opens (appending) the log file for `date`, owner-only. A file left group/world readable by
/// an earlier version is tightened too.
fn open_log_file(dir: &Path, date: time::Date) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::PermissionsExt as _;
    let file =
        std::fs::OpenOptions::new().append(true).create(true).mode_private().open(dir.join(log_file_name(date)))?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// The current UTC day's log file; moves to a new file when the day changes.
struct DailyLogFile<C: Fn() -> time::Date> {
    dir: std::path::PathBuf,
    today: C,
    date: time::Date,
    file: std::fs::File,
}

impl<C: Fn() -> time::Date> DailyLogFile<C> {
    fn open(dir: &Path, today: C) -> std::io::Result<Self> {
        let date = today();
        Ok(Self { dir: dir.to_path_buf(), file: open_log_file(dir, date)?, date, today })
    }
}

impl<C: Fn() -> time::Date> Write for DailyLogFile<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let date = (self.today)();
        if date != self.date {
            // If the new file cannot be opened, keep writing to the old one and try again on
            // the next batch.
            if let Ok(file) = open_log_file(&self.dir, date) {
                self.file = file;
                self.date = date;
            }
        }
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
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

/// Log targets (a crate or module, covering everything below it) that emit credential
/// material when verbose, with the most verbose level Bastion will ever record for them.
///
/// - `sspi` (debug): `#[instrument(ret)]` on `write_password_credentials` and friends prints the
///   encoded TSPasswordCreds (domain, user name and password) plus NTLM/Kerberos tokens.
/// - `ironrdp_connector::credssp` (debug): dumps every `TsRequest`, i.e. the NTLM challenge and
///   NetNTLMv2 response, which can be cracked offline.
/// - `tungstenite` (trace): prints the gateway WebSocket upgrade request including its
///   `Authorization` header, and then every frame of the session.
/// - `reqwest`, `hyper`, `hyper_util`, `h2` (trace): raw HTTP reads/writes and header parsing
///   for the gateway and KDC-proxy connections, which carry `Authorization` headers.
pub const CREDENTIAL_CAPS: &[(&str, Level)] = &[
    ("sspi", Level::WARN),
    ("ironrdp_connector::credssp", Level::INFO),
    ("tungstenite", Level::DEBUG),
    ("tokio_tungstenite", Level::DEBUG),
    ("reqwest", Level::DEBUG),
    ("hyper", Level::DEBUG),
    ("hyper_util", Level::DEBUG),
    ("h2", Level::DEBUG),
];

/// Whether an event or span from `target` at `level` may be recorded at all. Applied on top of
/// the user's filter, so no `BASTION_LOG` directive or settings level can enable what this
/// refuses.
pub fn credential_cap_allows(target: &str, level: &Level) -> bool {
    CREDENTIAL_CAPS.iter().all(|(capped, max)| {
        let inside = target.strip_prefix(capped).is_some_and(|rest| rest.is_empty() || rest.starts_with("::"));
        // More verbose levels compare greater.
        !inside || level <= max
    })
}

/// Builds the filter for the whole logging stack: the user's directive (`BASTION_LOG` if set,
/// else the settings level with noisy protocol crates capped at `warn`), and then the
/// credential caps, which the directive cannot override.
fn build_filter<S>(env_directive: Option<&str>, level: &str) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let directive = match env_directive {
        Some(d) => d.to_owned(),
        None => format!("{level},sspi=warn,ironrdp_tls=warn,wgpu_core=warn,wgpu_hal=warn,naga=warn,zbus=warn"),
    };
    let user = EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"));
    let caps = tracing_subscriber::filter::filter_fn(|meta| credential_cap_allows(meta.target(), meta.level()));
    user.and_then(caps)
}

/// Initialises global logging. `level` is an EnvFilter directive (e.g. "info", "bastion=debug").
pub fn init(paths: &AppPaths, level: &str) -> Result<LogGuard> {
    let dir = paths.log_dir();
    ensure_private_dir(&dir)?;
    let appender = DailyLogFile::open(&dir, || time::OffsetDateTime::now_utc().date())
        .with_context(|| format!("open a log file in {}", dir.display()))?;
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

    let filter = build_filter(std::env::var("BASTION_LOG").ok().as_deref(), level);

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
    fn credential_caps_cover_whole_module_trees_only() {
        // The line that prints the password: sspi::credssp::ts_request at DEBUG.
        assert!(!credential_cap_allows("sspi::credssp::ts_request", &Level::DEBUG));
        assert!(!credential_cap_allows("sspi", &Level::INFO));
        assert!(credential_cap_allows("sspi::credssp", &Level::WARN));
        assert!(!credential_cap_allows("ironrdp_connector::credssp", &Level::DEBUG));
        assert!(credential_cap_allows("ironrdp_connector::credssp", &Level::INFO));
        assert!(credential_cap_allows("ironrdp_connector::connection", &Level::TRACE));
        assert!(!credential_cap_allows("tungstenite::handshake::client", &Level::TRACE));
        assert!(credential_cap_allows("tungstenite::handshake::client", &Level::DEBUG));
        assert!(!credential_cap_allows("reqwest::connect::verbose", &Level::TRACE));
        // Names that merely start with a capped one are unaffected.
        assert!(credential_cap_allows("sspi_helper", &Level::TRACE));
        assert!(credential_cap_allows("bastion_session::engine", &Level::TRACE));
    }

    /// Runs `emit` under the filter `init` would install and returns what reached the log.
    fn logged(env_directive: Option<&str>, level: &str, emit: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::registry()
            .with(build_filter(env_directive, level))
            .with(fmt::layer().with_writer(move || writer.clone()).with_ansi(false).with_target(true));
        tracing::subscriber::with_default(subscriber, emit);
        String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
    }

    fn emit_everything() {
        // What sspi's `#[instrument(ret, level = "debug")]` expands to: a span carrying the
        // arguments and an event carrying the return value.
        let span = tracing::span!(target: "sspi::credssp::ts_request", Level::DEBUG, "write_password_credentials", credentials = "SPAN-SECRET");
        let _entered = span.enter();
        tracing::event!(target: "sspi::credssp::ts_request", Level::DEBUG, r#return = "RETURN-SECRET");
        tracing::event!(target: "sspi::ntlm", Level::TRACE, "NTLM-SECRET");
        tracing::event!(target: "ironrdp_connector::credssp", Level::DEBUG, message = "TSREQUEST-SECRET", "Send");
        tracing::event!(target: "tungstenite::handshake::client", Level::TRACE, "Request: Authorization: Basic BASIC-SECRET");
        tracing::event!(target: "reqwest::connect::verbose", Level::TRACE, "write: HTTP-SECRET");
        tracing::event!(target: "sspi::kerberos", Level::WARN, "sspi-warning");
        tracing::event!(target: "ironrdp_connector::credssp", Level::INFO, "credssp-info");
        tracing::event!(target: "ironrdp_connector::connection", Level::DEBUG, "connector-debug");
        tracing::event!(target: "bastion_session::engine", Level::DEBUG, "engine-debug");
        tracing::event!(target: "bastion_session::engine", Level::INFO, "engine-info");
    }

    #[test]
    fn no_directive_can_enable_credential_logging() {
        // Every way a user can ask for verbose logs, including naming the modules outright.
        let directives = [
            (Some("debug"), "info"),
            (Some("trace"), "info"),
            (Some("trace,sspi=trace,sspi::credssp::ts_request=trace,ironrdp_connector::credssp=trace"), "info"),
            (Some("sspi=debug,tungstenite=trace,reqwest=trace,ironrdp_connector=trace"), "info"),
            (None, "trace"),
            (None, "debug,sspi=debug"),
            (None, "info,sspi::credssp::ts_request=trace"),
        ];
        for (env, level) in directives {
            let out = logged(env, level, emit_everything);
            assert!(!out.contains("SECRET"), "{env:?}/{level}: credential material was logged:\n{out}");
            assert!(!out.contains("write_password_credentials"), "{env:?}/{level}: sspi span was recorded:\n{out}");
        }
    }

    #[test]
    fn verbose_logging_still_works_for_everything_else() {
        let out = logged(Some("debug"), "info", emit_everything);
        for expected in ["sspi-warning", "credssp-info", "connector-debug", "engine-debug", "engine-info"] {
            assert!(out.contains(expected), "missing {expected}:\n{out}");
        }
        // Default settings: info, with sspi warnings.
        let out = logged(None, "info", emit_everything);
        assert!(out.contains("engine-info") && out.contains("sspi-warning") && out.contains("credssp-info"), "{out}");
        assert!(!out.contains("engine-debug") && !out.contains("connector-debug"), "{out}");
        // A directive that does not parse falls back to info rather than to nothing.
        let out = logged(Some("not a=directive=at all"), "info", emit_everything);
        assert!(out.contains("engine-info") && !out.contains("engine-debug") && !out.contains("SECRET"), "{out}");
    }

    #[test]
    fn log_files_are_private_and_roll_over_by_day() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let day = std::rc::Rc::new(std::cell::Cell::new(time::macros::date!(2026 - 11 - 17)));
        let first = dir.path().join("bastion.2026-11-17.log");
        // Left behind world-readable by an earlier version.
        std::fs::write(&first, "earlier\n").unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o644)).unwrap();

        let clock = day.clone();
        let mut log = DailyLogFile::open(dir.path(), move || clock.get()).unwrap();
        assert_eq!(mode(&first), 0o600, "existing file is tightened");
        log.write_all(b"one\n").unwrap();
        day.set(time::macros::date!(2026 - 11 - 18));
        log.write_all(b"two\n").unwrap();
        log.flush().unwrap();

        let second = dir.path().join("bastion.2026-11-18.log");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "earlier\none\n", "appends, never truncates");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "two\n");
        assert_eq!(mode(&second), 0o600, "new files are created owner-only");
        // Names are the ones log maintenance recognises.
        assert_eq!(log_file_date(&log_file_name(day.get())), Some((day.get(), false)));
    }

    #[test]
    fn masks_values() {
        assert_eq!(redact("gw_pass: \"abc def\", x: 1"), "gw_pass: <redacted>, x: 1");
        assert_eq!(redact("password=hunter2 next"), "password=<redacted> next");
        assert_eq!(redact("compass: north"), "compass: north");
        assert_eq!(redact("no secrets here"), "no secrets here");
    }
}
