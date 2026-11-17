//! Certificate trust store ("known hosts" for RDP and RD Gateway endpoints).
//!
//! Policy:
//! 1. A certificate that chains to a system root and matches the hostname is trusted outright.
//! 2. Otherwise the leaf certificate's SHA-256 fingerprint is compared with a pinned one:
//!    - match       → trusted
//!    - no pin      → user is asked (Trust-On-First-Use); accepting pins it
//!    - different   → LOUD warning; the user must explicitly replace the pin
//!
//! The file is `~/.config/bastion/known_hosts.toml` (mode 0600).
//!
//! Several Bastion processes can run at once (opening an `.rdp` file starts another one while
//! the first sits in the tray), so the file on disk is the source of truth: every change is
//! applied to a fresh read of the file under an exclusive lock, and [`TrustStore::check`]
//! notices when another process changed the file, so a pin forgotten elsewhere stops being
//! honoured here and is never written back.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::paths::{AppPaths, FileStamp, file_stamp, lock_exclusive, write_private_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointKind {
    Gateway,
    Rdp,
}

impl EndpointKind {
    fn tag(self) -> &'static str {
        match self {
            EndpointKind::Gateway => "gateway",
            EndpointKind::Rdp => "rdp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pin {
    /// Uppercase hex SHA-256 of the leaf certificate DER, colon-separated.
    pub sha256: String,
    /// When the pin was created (RFC 3339).
    pub pinned_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustStatus {
    Pinned,
    Unknown,
    Mismatch { pinned: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    #[serde(default)]
    hosts: BTreeMap<String, Pin>,
}

#[derive(Debug)]
pub struct TrustStore {
    path: Option<PathBuf>,
    file: TrustFile,
    /// What the file looked like when `file` was read from (or written to) it.
    stamp: Option<FileStamp>,
    /// Contents re-read by [`TrustStore::check`] (which only has `&self`) after another
    /// process changed the file, with the stamp they belong to.
    fresh: Mutex<Option<(Option<FileStamp>, TrustFile)>>,
}

/// A missing file is an empty store; an unreadable or malformed one is an error.
fn read_trust_file(path: &Path) -> Result<TrustFile> {
    match std::fs::read_to_string(path) {
        Ok(t) => toml::from_str(&t).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustFile::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn status(hosts: &BTreeMap<String, Pin>, key: &str, cert_der: &[u8]) -> TrustStatus {
    match hosts.get(key) {
        None => TrustStatus::Unknown,
        Some(pin) if pin.sha256 == fingerprint_sha256(cert_der) => TrustStatus::Pinned,
        Some(pin) => TrustStatus::Mismatch { pinned: pin.sha256.clone() },
    }
}

pub fn fingerprint_sha256(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    let mut out = String::with_capacity(95);
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

fn key(kind: EndpointKind, endpoint: &str) -> String {
    format!("{}|{}", kind.tag(), endpoint.to_ascii_lowercase())
}

impl TrustStore {
    pub fn load(paths: &AppPaths) -> Result<Self> {
        let path = paths.trust_file();
        // Stamp first: if the file is replaced in between, the stamp is the older one and the
        // next check simply re-reads.
        let stamp = file_stamp(&path);
        let file = read_trust_file(&path)?;
        Ok(Self { path: Some(path), file, stamp, fresh: Mutex::new(None) })
    }

    pub fn in_memory() -> Self {
        Self { path: None, file: TrustFile::default(), stamp: None, fresh: Mutex::new(None) }
    }

    /// Compares a certificate with the pin for an endpoint, as currently stored on disk: a pin
    /// that another Bastion process removed or replaced since this store was loaded is not
    /// honoured.
    pub fn check(&self, kind: EndpointKind, endpoint: &str, cert_der: &[u8]) -> TrustStatus {
        let key = key(kind, endpoint);
        let Some(path) = &self.path else { return status(&self.file.hosts, &key, cert_der) };
        let now = file_stamp(path);
        if now == self.stamp {
            return status(&self.file.hosts, &key, cert_der);
        }
        let mut fresh = self.fresh.lock().unwrap_or_else(PoisonError::into_inner);
        if fresh.as_ref().map(|(stamp, _)| *stamp) != Some(now) {
            // Fail closed: if the file can no longer be read, nothing is pinned (the user is
            // asked) rather than trusting what this process remembers.
            let file = read_trust_file(path).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Cannot re-read the trusted certificates; treating all as unknown");
                TrustFile::default()
            });
            *fresh = Some((now, file));
        }
        match fresh.as_ref() {
            Some((_, file)) => status(&file.hosts, &key, cert_der),
            None => TrustStatus::Unknown,
        }
    }

    pub fn pin(&mut self, kind: EndpointKind, endpoint: &str, cert_der: &[u8]) -> Result<()> {
        let now =
            time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default();
        let key = key(kind, endpoint);
        let pin = Pin { sha256: fingerprint_sha256(cert_der), pinned_at: now };
        self.mutate(|hosts| {
            hosts.insert(key.clone(), pin.clone());
        })
    }

    pub fn forget(&mut self, kind: EndpointKind, endpoint: &str) -> Result<()> {
        let key = key(kind, endpoint);
        self.mutate(|hosts| {
            hosts.remove(&key);
        })
    }

    /// Pins as of the last load, change or [`TrustStore::reload`] in this process.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Pin)> {
        self.file.hosts.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Re-reads the file if another process changed it, so [`TrustStore::entries`] is current.
    pub fn reload(&mut self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let stamp = file_stamp(path);
        if stamp != self.stamp {
            self.file = read_trust_file(path)?;
            self.stamp = stamp;
            *self.fresh.get_mut().unwrap_or_else(PoisonError::into_inner) = None;
        }
        Ok(())
    }

    /// Applies one change on top of what is on disk *now* (not this process's possibly stale
    /// copy) and writes it back, all under the lock shared with other Bastion processes.
    fn mutate(&mut self, change: impl Fn(&mut BTreeMap<String, Pin>)) -> Result<()> {
        let Some(path) = self.path.clone() else {
            change(&mut self.file.hosts);
            return Ok(());
        };
        let written = (|| {
            let _lock = lock_exclusive(&path)?;
            let mut file = read_trust_file(&path)?;
            change(&mut file.hosts);
            write_private_atomic(&path, toml::to_string_pretty(&file)?.as_bytes())?;
            Ok::<_, anyhow::Error>((file, file_stamp(&path)))
        })();
        match written {
            Ok((file, stamp)) => {
                self.file = file;
                self.stamp = stamp;
                *self.fresh.get_mut().unwrap_or_else(PoisonError::into_inner) = None;
                Ok(())
            }
            Err(e) => {
                // Nothing was written. The decision still holds for this process (as before),
                // so a read-only config directory does not turn into an endless prompt.
                change(&mut self.file.hosts);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tofu_flow() {
        let mut s = TrustStore::in_memory();
        let a = b"cert-a";
        let b = b"cert-b";
        assert_eq!(s.check(EndpointKind::Rdp, "PC:3389", a), TrustStatus::Unknown);
        s.pin(EndpointKind::Rdp, "pc:3389", a).unwrap();
        assert_eq!(s.check(EndpointKind::Rdp, "PC:3389", a), TrustStatus::Pinned);
        assert!(matches!(s.check(EndpointKind::Rdp, "pc:3389", b), TrustStatus::Mismatch { .. }));
        // Kinds are separate namespaces.
        assert_eq!(s.check(EndpointKind::Gateway, "pc:3389", a), TrustStatus::Unknown);
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint_sha256(b"");
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(fp.starts_with("E3:B0:C4:42"));
    }

    fn two_processes() -> (tempfile::TempDir, AppPaths, TrustStore, TrustStore) {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut first = TrustStore::load(&paths).unwrap();
        first.pin(EndpointKind::Gateway, "rdg.corp.com:443", b"compromised").unwrap();
        first.pin(EndpointKind::Rdp, "pc01:3389", b"pc01").unwrap();
        // "Tray" instance, loaded before the other one changes anything.
        let stale = TrustStore::load(&paths).unwrap();
        (dir, paths, stale, first)
    }

    #[test]
    fn pin_forgotten_by_another_process_is_no_longer_trusted() {
        let (_dir, _paths, stale, mut other) = two_processes();
        assert_eq!(stale.check(EndpointKind::Gateway, "rdg.corp.com:443", b"compromised"), TrustStatus::Pinned);
        other.forget(EndpointKind::Gateway, "rdg.corp.com:443").unwrap();
        assert_eq!(stale.check(EndpointKind::Gateway, "rdg.corp.com:443", b"compromised"), TrustStatus::Unknown);
        // Untouched pins still work, and so does a pin replaced elsewhere.
        assert_eq!(stale.check(EndpointKind::Rdp, "pc01:3389", b"pc01"), TrustStatus::Pinned);
        other.pin(EndpointKind::Rdp, "pc01:3389", b"renewed").unwrap();
        assert_eq!(stale.check(EndpointKind::Rdp, "pc01:3389", b"renewed"), TrustStatus::Pinned);
        assert!(matches!(stale.check(EndpointKind::Rdp, "pc01:3389", b"pc01"), TrustStatus::Mismatch { .. }));
    }

    #[test]
    fn stale_process_does_not_write_a_forgotten_pin_back() {
        let (_dir, paths, mut stale, mut other) = two_processes();
        other.forget(EndpointKind::Gateway, "rdg.corp.com:443").unwrap();
        other.pin(EndpointKind::Rdp, "new:3389", b"new").unwrap();

        // The stale process approves an unrelated certificate (rewrites the file).
        stale.pin(EndpointKind::Rdp, "pc02:3389", b"pc02").unwrap();

        let disk = TrustStore::load(&paths).unwrap();
        let keys: Vec<&str> = disk.entries().map(|(k, _)| k).collect();
        assert_eq!(keys, ["rdp|new:3389", "rdp|pc01:3389", "rdp|pc02:3389"], "one change on top of the fresh file");
        assert_eq!(stale.check(EndpointKind::Gateway, "rdg.corp.com:443", b"compromised"), TrustStatus::Unknown);
        // Its own view was refreshed by the write.
        assert_eq!(stale.entries().count(), 3);

        // Forgetting from a stale process keeps the other's additions too.
        other.pin(EndpointKind::Rdp, "late:3389", b"late").unwrap();
        stale.forget(EndpointKind::Rdp, "pc02:3389").unwrap();
        let disk = TrustStore::load(&paths).unwrap();
        let keys: Vec<&str> = disk.entries().map(|(k, _)| k).collect();
        assert_eq!(keys, ["rdp|late:3389", "rdp|new:3389", "rdp|pc01:3389"]);
    }

    #[test]
    fn reload_refreshes_the_listing_and_file_stays_private() {
        let (_dir, paths, mut stale, mut other) = two_processes();
        other.forget(EndpointKind::Gateway, "rdg.corp.com:443").unwrap();
        assert_eq!(stale.entries().count(), 2);
        stale.reload().unwrap();
        assert_eq!(stale.entries().count(), 1);
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(paths.trust_file()).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn unreadable_file_fails_closed_and_is_not_overwritten() {
        let (_dir, paths, mut stale, _other) = two_processes();
        std::fs::write(paths.trust_file(), "hosts = not toml").unwrap();
        assert_eq!(stale.check(EndpointKind::Rdp, "pc01:3389", b"pc01"), TrustStatus::Unknown);
        assert!(stale.pin(EndpointKind::Rdp, "pc03:3389", b"pc03").is_err());
        assert_eq!(std::fs::read_to_string(paths.trust_file()).unwrap(), "hosts = not toml");
    }
}
