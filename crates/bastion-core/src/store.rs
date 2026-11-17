//! Persistent profile storage (`profiles.toml`) and app-wide settings.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths::{AppPaths, write_private_atomic};
use crate::profile::Profile;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProfilesFile {
    #[serde(default, rename = "profile")]
    profiles: Vec<Profile>,
}

/// In-memory list of profiles backed by a TOML file.
#[derive(Debug)]
pub struct ProfileStore {
    path: PathBuf,
    profiles: Vec<Profile>,
}

impl ProfileStore {
    pub fn load(paths: &AppPaths) -> Result<Self> {
        let path = paths.profiles_file();
        let profiles = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let file: ProfilesFile = toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
                file.profiles
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        Ok(Self { path, profiles })
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn get(&self, id: Uuid) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Inserts or replaces (by id) and persists.
    pub fn upsert(&mut self, profile: Profile) -> Result<()> {
        match self.profiles.iter_mut().find(|p| p.id == profile.id) {
            Some(existing) => *existing = profile,
            None => self.profiles.push(profile),
        }
        self.save()
    }

    pub fn remove(&mut self, id: Uuid) -> Result<Option<Profile>> {
        let idx = self.profiles.iter().position(|p| p.id == id);
        let removed = idx.map(|i| self.profiles.remove(i));
        self.save()?;
        Ok(removed)
    }

    fn save(&self) -> Result<()> {
        let file = ProfilesFile { profiles: self.profiles.clone() };
        let text = toml::to_string_pretty(&file)?;
        write_private_atomic(&self.path, text.as_bytes())
    }
}

/// App-wide preferences (not per connection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    /// Key chord that releases keyboard grab / opens the session toolbar.
    pub release_chord: String,
    /// Send Super/Alt+Tab etc. to the remote while the session is focused (Wayland shortcut inhibit).
    pub grab_system_shortcuts: bool,
    pub log_level: String,
    /// Keep the session bar visible (pinned from the bar itself).
    pub pin_session_bar: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            release_chord: "Ctrl+Alt+Home".to_owned(),
            grab_system_shortcuts: true,
            log_level: "info".to_owned(),
            pin_session_bar: false,
        }
    }
}

impl AppSettings {
    pub fn load(paths: &AppPaths) -> Self {
        std::fs::read_to_string(paths.settings_file()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        write_private_atomic(&paths.settings_file(), toml::to_string_pretty(self)?.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_session_bar_is_remembered_and_off_for_old_settings() {
        let old: AppSettings = toml::from_str("grab_system_shortcuts = false").unwrap();
        assert!(!old.pin_session_bar);
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let s = AppSettings { pin_session_bar: true, ..Default::default() };
        s.save(&paths).unwrap();
        assert!(AppSettings::load(&paths).pin_session_bar);
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut store = ProfileStore::load(&paths).unwrap();
        let p = Profile { name: "A".into(), host: "a.example".into(), ..Default::default() };
        let id = p.id;
        store.upsert(p).unwrap();
        let store2 = ProfileStore::load(&paths).unwrap();
        assert_eq!(store2.get(id).unwrap().host, "a.example");

        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(paths.profiles_file()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
