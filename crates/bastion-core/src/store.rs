//! Persistent profile storage (`profiles.toml`) and app-wide settings.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths::{AppPaths, FileStamp, file_stamp, lock_exclusive, write_private_atomic};
use crate::profile::Profile;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProfilesFile {
    #[serde(default, rename = "profile")]
    profiles: Vec<Profile>,
}

/// In-memory list of profiles backed by a TOML file.
///
/// Several Bastion processes can run at once, so changes are never written from this copy:
/// each one is applied to a fresh read of the file under an exclusive lock, which keeps what
/// other processes saved or deleted in the meantime.
#[derive(Debug)]
pub struct ProfileStore {
    path: PathBuf,
    profiles: Vec<Profile>,
    /// What the file looked like when `profiles` was read from (or written to) it.
    stamp: Option<FileStamp>,
}

/// A missing file is an empty list; an unreadable or malformed one is an error.
fn read_profiles(path: &Path) -> Result<Vec<Profile>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let file: ProfilesFile = toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            Ok(file.profiles)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn upsert_into(profiles: &mut Vec<Profile>, profile: &Profile) {
    match profiles.iter_mut().find(|p| p.id == profile.id) {
        Some(existing) => *existing = profile.clone(),
        None => profiles.push(profile.clone()),
    }
}

fn remove_from(profiles: &mut Vec<Profile>, id: Uuid) -> Option<Profile> {
    let idx = profiles.iter().position(|p| p.id == id)?;
    Some(profiles.remove(idx))
}

impl ProfileStore {
    pub fn load(paths: &AppPaths) -> Result<Self> {
        let path = paths.profiles_file();
        // Stamp first: if the file is replaced in between, the next reload simply re-reads.
        let stamp = file_stamp(&path);
        let profiles = read_profiles(&path)?;
        Ok(Self { path, profiles, stamp })
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn get(&self, id: Uuid) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Picks up changes saved by another Bastion process. Cheap (one `stat`) when nothing
    /// changed, so it can run every frame. A file that cannot be read is reported once and
    /// this copy is kept until the file changes again.
    pub fn reload(&mut self) -> Result<()> {
        let stamp = file_stamp(&self.path);
        if stamp == self.stamp {
            return Ok(());
        }
        self.stamp = stamp;
        self.profiles = read_profiles(&self.path)?;
        Ok(())
    }

    /// Changes only what `change` touches on the profile with this id as it is on disk *now*,
    /// so settings changed by another process in the meantime are kept. Returns the updated
    /// profile, or `None` if it no longer exists (it is not brought back).
    pub fn update(&mut self, id: Uuid, change: impl Fn(&mut Profile)) -> Result<Option<Profile>> {
        let saved = self.update_file(|profiles| {
            let p = profiles.iter_mut().find(|p| p.id == id)?;
            change(p);
            Some(p.clone())
        });
        match saved {
            Ok((updated, profiles, stamp)) => {
                self.profiles = profiles;
                self.stamp = stamp;
                Ok(updated)
            }
            Err(e) => {
                if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
                    change(p);
                }
                Err(e)
            }
        }
    }

    /// Inserts or replaces (by id) and persists.
    pub fn upsert(&mut self, profile: Profile) -> Result<()> {
        let saved = self.update_file(|profiles| upsert_into(profiles, &profile));
        match saved {
            Ok(((), profiles, stamp)) => {
                self.profiles = profiles;
                self.stamp = stamp;
                Ok(())
            }
            Err(e) => {
                // Not saved; as before, this process still shows what the user entered.
                upsert_into(&mut self.profiles, &profile);
                Err(e)
            }
        }
    }

    pub fn remove(&mut self, id: Uuid) -> Result<Option<Profile>> {
        let mine = remove_from(&mut self.profiles, id);
        let (on_disk, profiles, stamp) = self.update_file(|profiles| remove_from(profiles, id))?;
        self.profiles = profiles;
        self.stamp = stamp;
        // Another process may have deleted it already; the caller still gets the profile it
        // asked to remove (to clean up its keyring entries).
        Ok(on_disk.or(mine))
    }

    /// Applies one change on top of what is on disk *now* (not this process's possibly stale
    /// copy) and writes it back, all under the lock shared with other Bastion processes.
    fn update_file<T>(
        &self,
        change: impl FnOnce(&mut Vec<Profile>) -> T,
    ) -> Result<(T, Vec<Profile>, Option<FileStamp>)> {
        let _lock = lock_exclusive(&self.path)?;
        let mut profiles = read_profiles(&self.path)?;
        let out = change(&mut profiles);
        let file = ProfilesFile { profiles };
        let text = toml::to_string_pretty(&file)?;
        write_private_atomic(&self.path, text.as_bytes())?;
        Ok((out, file.profiles, file_stamp(&self.path)))
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

    #[test]
    fn stale_process_does_not_undo_another_process_changes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut other = ProfileStore::load(&paths).unwrap();
        let mut a = Profile { name: "A".into(), host: "a.example".into(), ..Default::default() };
        a.security.allow_insecure_tls = true;
        let deleted = Profile { name: "Gone".into(), host: "gone.example".into(), ..Default::default() };
        other.upsert(a.clone()).unwrap();
        other.upsert(deleted.clone()).unwrap();

        // "Tray" instance with the old state.
        let mut stale = ProfileStore::load(&paths).unwrap();

        // Elsewhere: the insecure setting is switched off, one profile deleted, one added.
        a.security.allow_insecure_tls = false;
        other.upsert(a.clone()).unwrap();
        other.remove(deleted.id).unwrap();
        let added = Profile { name: "New".into(), host: "new.example".into(), ..Default::default() };
        other.upsert(added.clone()).unwrap();

        // The stale instance saves an unrelated profile.
        let mine = Profile { name: "Mine".into(), host: "mine.example".into(), ..Default::default() };
        stale.upsert(mine.clone()).unwrap();

        let disk = ProfileStore::load(&paths).unwrap();
        let names: Vec<&str> = disk.profiles().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["A", "New", "Mine"]);
        assert!(!disk.get(a.id).unwrap().security.allow_insecure_tls, "security setting must not be reverted");
        // The stale instance now sees the same thing.
        assert_eq!(stale.profiles(), disk.profiles());

        // Removing from a stale instance keeps later additions, and removing something that is
        // already gone on disk still hands back the profile.
        let mut stale2 = ProfileStore::load(&paths).unwrap();
        let late = Profile { name: "Late".into(), host: "late.example".into(), ..Default::default() };
        other.upsert(late).unwrap();
        other.remove(mine.id).unwrap();
        assert_eq!(stale2.remove(mine.id).unwrap().map(|p| p.name), Some("Mine".to_owned()));
        assert_eq!(stale2.remove(added.id).unwrap().map(|p| p.name), Some("New".to_owned()));
        let disk = ProfileStore::load(&paths).unwrap();
        let names: Vec<&str> = disk.profiles().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["A", "Late"]);
        assert_eq!(stale2.remove(Uuid::new_v4()).unwrap(), None);

        other.reload().unwrap();
        assert_eq!(other.profiles(), disk.profiles());
    }

    #[test]
    fn stale_process_updating_the_same_profile_keeps_other_changes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut other = ProfileStore::load(&paths).unwrap();
        let mut a = Profile { name: "A".into(), host: "a.example".into(), ..Default::default() };
        a.security.allow_insecure_tls = true;
        other.upsert(a.clone()).unwrap();
        let mut stale = ProfileStore::load(&paths).unwrap();

        a.security.allow_insecure_tls = false;
        other.upsert(a.clone()).unwrap();

        // The stale process remembers the username typed into its password prompt.
        let updated = stale.update(a.id, |p| p.username = "bob".into()).unwrap().unwrap();
        assert!(!updated.security.allow_insecure_tls, "the connection must use the current setting");
        let disk = ProfileStore::load(&paths).unwrap();
        let p = disk.get(a.id).unwrap();
        assert_eq!(p.username, "bob");
        assert!(!p.security.allow_insecure_tls, "security setting must not be reverted");

        // A profile deleted elsewhere is not brought back.
        other.remove(a.id).unwrap();
        assert_eq!(stale.update(a.id, |p| p.username = "eve".into()).unwrap(), None);
        assert!(ProfileStore::load(&paths).unwrap().profiles().is_empty());
    }

    #[test]
    fn reload_picks_up_changes_only_when_the_file_changed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut other = ProfileStore::load(&paths).unwrap();
        let mut stale = ProfileStore::load(&paths).unwrap();
        let p = Profile { name: "A".into(), host: "a.example".into(), ..Default::default() };
        other.upsert(p.clone()).unwrap();
        stale.reload().unwrap();
        assert_eq!(stale.profiles(), other.profiles());
        stale.reload().unwrap();
        // A malformed file is reported once, and the last good list is kept.
        std::fs::write(paths.profiles_file(), "profile = 3").unwrap();
        assert!(stale.reload().is_err());
        assert!(stale.reload().is_ok());
        assert_eq!(stale.profiles().len(), 1);
    }

    #[test]
    fn malformed_file_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut store = ProfileStore::load(&paths).unwrap();
        let p = Profile { name: "A".into(), host: "a.example".into(), ..Default::default() };
        store.upsert(p.clone()).unwrap();
        std::fs::write(paths.profiles_file(), "profile = 3").unwrap();
        assert!(store.upsert(Profile { host: "b.example".into(), ..Default::default() }).is_err());
        assert!(store.remove(p.id).is_err());
        assert_eq!(std::fs::read_to_string(paths.profiles_file()).unwrap(), "profile = 3");
    }
}
