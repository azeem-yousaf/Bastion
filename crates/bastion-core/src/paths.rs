//! XDG-compliant locations for Bastion's files.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

pub const APP_NAME: &str = "bastion";

#[derive(Debug, Clone)]
pub struct AppPaths {
    /// ~/.config/bastion
    pub config_dir: PathBuf,
    /// ~/.local/state/bastion (logs)
    pub state_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("", "", APP_NAME).context("cannot determine home directory")?;
        let config_dir = dirs.config_dir().to_path_buf();
        let state_dir = dirs.state_dir().map(Path::to_path_buf).unwrap_or_else(|| dirs.data_local_dir().join("state"));
        Ok(Self { config_dir, state_dir })
    }

    /// For tests / portable mode.
    pub fn rooted(root: &Path) -> Self {
        Self { config_dir: root.join("config"), state_dir: root.join("state") }
    }

    pub fn profiles_file(&self) -> PathBuf {
        self.config_dir.join("profiles.toml")
    }

    pub fn trust_file(&self) -> PathBuf {
        self.config_dir.join("known_hosts.toml")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.toml")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.state_dir.join("logs")
    }
}

/// Creates `dir` (and parents) with mode 0700.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create directory {}", dir.display()))?;
    } else {
        let meta = std::fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Atomically writes `contents` to `path` with mode 0600 (write temp file, fsync, rename).
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = path.parent().context("path has no parent")?;
    ensure_private_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Exclusive advisory lock guarding read-modify-write cycles on a config file shared by every
/// Bastion process of this user. Released when dropped.
#[derive(Debug)]
pub struct FileLock {
    _file: std::fs::File,
}

/// Takes an exclusive `flock` on `.<name>.lock` next to `path` (created 0600), waiting for
/// another process that holds it. Holders only read and rewrite one small file, so the wait is
/// short.
pub fn lock_exclusive(path: &Path) -> Result<FileLock> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = path.parent().context("path has no parent")?;
    ensure_private_dir(dir)?;
    let lock_path = dir.join(format!(".{}.lock", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    file.lock().with_context(|| format!("lock {}", lock_path.display()))?;
    Ok(FileLock { _file: file })
}

/// Identity of a file's current contents: changes whenever another process replaces the file
/// (every save renames a new inode into place) or writes to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileStamp {
    ino: u64,
    len: u64,
    mtime: (i64, i64),
}

/// `None` when the file does not exist (or cannot be examined).
pub(crate) fn file_stamp(path: &Path) -> Option<FileStamp> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).ok()?;
    Some(FileStamp { ino: meta.ino(), len: meta.len(), mtime: (meta.mtime(), meta.mtime_nsec()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_exclusive_between_holders_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config").join("known_hosts.toml");
        let held = lock_exclusive(&target).unwrap();
        let lock_path = dir.path().join("config").join(".known_hosts.toml.lock");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777, 0o600);

        // A second open file description (what another process would have) cannot take it.
        let other = std::fs::OpenOptions::new().write(true).open(&lock_path).unwrap();
        assert!(other.try_lock().is_err(), "lock must be held exclusively");
        drop(held);
        other.try_lock().expect("released when the guard is dropped");
    }

    #[test]
    fn stamp_changes_when_the_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config").join("f.toml");
        assert_eq!(file_stamp(&path), None);
        write_private_atomic(&path, b"a = 1\n").unwrap();
        let first = file_stamp(&path).unwrap();
        assert_eq!(file_stamp(&path), Some(first));
        // Same length, written straight after: still seen as a different file.
        write_private_atomic(&path, b"a = 2\n").unwrap();
        assert_ne!(file_stamp(&path), Some(first));
    }
}
