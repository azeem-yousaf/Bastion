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

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::paths::{AppPaths, write_private_atomic};

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
        let file = match std::fs::read_to_string(&path) {
            Ok(t) => toml::from_str(&t).with_context(|| format!("parse {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrustFile::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path: Some(path), file })
    }

    pub fn in_memory() -> Self {
        Self { path: None, file: TrustFile::default() }
    }

    pub fn check(&self, kind: EndpointKind, endpoint: &str, cert_der: &[u8]) -> TrustStatus {
        match self.file.hosts.get(&key(kind, endpoint)) {
            None => TrustStatus::Unknown,
            Some(pin) if pin.sha256 == fingerprint_sha256(cert_der) => TrustStatus::Pinned,
            Some(pin) => TrustStatus::Mismatch { pinned: pin.sha256.clone() },
        }
    }

    pub fn pin(&mut self, kind: EndpointKind, endpoint: &str, cert_der: &[u8]) -> Result<()> {
        let now =
            time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default();
        self.file.hosts.insert(key(kind, endpoint), Pin { sha256: fingerprint_sha256(cert_der), pinned_at: now });
        self.save()
    }

    pub fn forget(&mut self, kind: EndpointKind, endpoint: &str) -> Result<()> {
        self.file.hosts.remove(&key(kind, endpoint));
        self.save()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &Pin)> {
        self.file.hosts.iter().map(|(k, v)| (k.as_str(), v))
    }

    fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            write_private_atomic(path, toml::to_string_pretty(&self.file)?.as_bytes())?;
        }
        Ok(())
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
}
