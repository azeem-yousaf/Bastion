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
