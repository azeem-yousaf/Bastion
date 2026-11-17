//! Password storage in the OS keyring (Secret Service: KWallet / GNOME Keyring / KeePassXC).
//!
//! Passwords never touch Bastion's own files. In memory they are held in [`Secret`],
//! which zeroizes on drop and never prints its contents.

use std::sync::{Arc, OnceLock};

use anyhow::{Context as _, Result, anyhow};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SERVICE: &str = "bastion-rdp";

/// A password that is wiped from memory on drop and redacted in Debug output.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Mutable access for UI text fields (egui needs a `&mut String`).
    pub fn as_mut_string(&mut self) -> &mut String {
        &mut self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Which credential of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Host,
    Gateway,
}

impl SecretKind {
    fn suffix(self) -> &'static str {
        match self {
            SecretKind::Host => "host",
            SecretKind::Gateway => "gateway",
        }
    }
}

static INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn init() -> Result<()> {
    INIT.get_or_init(|| match zbus_secret_service_keyring_store::Store::new() {
        Ok(store) => {
            let store: Arc<keyring_core::CredentialStore> = store;
            keyring_core::set_default_store(store);
            Ok(())
        }
        Err(e) => Err(format!("Secret Service unavailable: {e}")),
    })
    .clone()
    .map_err(|e| anyhow!(e))
}

fn entry(profile: Uuid, kind: SecretKind) -> Result<keyring_core::Entry> {
    init()?;
    keyring_core::Entry::new(SERVICE, &format!("{profile}:{}", kind.suffix())).context("open keyring entry")
}

/// Whether a keyring backend is reachable (used to grey out "Remember password").
pub fn keyring_available() -> bool {
    init().is_ok()
}

pub fn load(profile: Uuid, kind: SecretKind) -> Result<Option<Secret>> {
    match entry(profile, kind)?.get_password() {
        Ok(pw) => Ok(Some(Secret::new(pw))),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("keyring read failed: {e}")),
    }
}

pub fn store(profile: Uuid, kind: SecretKind, secret: &Secret) -> Result<()> {
    entry(profile, kind)?.set_password(secret.expose()).map_err(|e| anyhow!("keyring write failed: {e}"))
}

pub fn delete(profile: Uuid, kind: SecretKind) -> Result<()> {
    match entry(profile, kind)?.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow!("keyring delete failed: {e}")),
    }
}

/// Removes every secret belonging to a profile (called when a profile is deleted).
pub fn delete_all(profile: Uuid) -> Result<()> {
    delete(profile, SecretKind::Host)?;
    delete(profile, SecretKind::Gateway)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }
}
