//! File clipboard support: local file lists (upload) and remote downloads into a private
//! temporary directory.

pub(crate) mod download;
pub(crate) mod local;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Hard bounds applied to every file transfer, in either direction.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    /// Total bytes in one copy (all files together). Also the per-file cap.
    pub(crate) max_total_bytes: u64,
    /// Entries (files + directories) in one copy.
    pub(crate) max_files: usize,
}

/// Default entry cap. Far above real-world copies, far below the 100k the PDU decoder accepts.
pub(crate) const DEFAULT_MAX_FILES: usize = 10_000;

/// Max path components accepted from the remote.
const MAX_REMOTE_DEPTH: usize = 33;
/// Linux NAME_MAX.
const MAX_COMPONENT_BYTES: usize = 255;

/// Why a remote file name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathRejection {
    Empty,
    Nul,
    Absolute,
    Traversal,
    DeviceName,
    ControlChar,
    Colon,
    TooLong,
    TooDeep,
}

/// Validates a remote `relative_path` + `name` pair (as delivered by `Cliprdr`, which already
/// sanitized it once) and returns the path components to create below the download root.
///
/// This is a second, strict line of defence: anything suspicious is rejected outright instead
/// of being repaired.
pub(crate) fn sanitize_remote_path(relative: Option<&str>, name: &str) -> Result<Vec<String>, PathRejection> {
    let joined = match relative {
        Some(r) if !r.is_empty() => format!("{r}\\{name}"),
        _ => name.to_owned(),
    };
    if joined.is_empty() {
        return Err(PathRejection::Empty);
    }
    if joined.contains('\0') {
        return Err(PathRejection::Nul);
    }
    let bytes = joined.as_bytes();
    if bytes[0] == b'/' || bytes[0] == b'\\' || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(PathRejection::Absolute);
    }
    let mut out = Vec::new();
    for component in joined.split(['\\', '/']) {
        match component {
            "" => return Err(PathRejection::Empty),
            "." | ".." => return Err(PathRejection::Traversal),
            _ => {}
        }
        // Windows strips trailing dots/spaces, so "..." or ".. " would also mean "..".
        if component.trim_end_matches(['.', ' ']).is_empty() {
            return Err(PathRejection::Traversal);
        }
        if component.chars().any(char::is_control) {
            return Err(PathRejection::ControlChar);
        }
        if component.contains(':') {
            return Err(PathRejection::Colon);
        }
        if ironrdp_cliprdr::is_windows_device_name(component.trim_end_matches(['.', ' '])) {
            return Err(PathRejection::DeviceName);
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(PathRejection::TooLong);
        }
        out.push(component.to_owned());
        if out.len() > MAX_REMOTE_DEPTH {
            return Err(PathRejection::TooDeep);
        }
    }
    Ok(out)
}

/// How long abandoned download directories (e.g. after a crash) are kept.
const STALE_AFTER: Duration = Duration::from_secs(24 * 3600);
pub(crate) const DOWNLOAD_PREFIX: &str = "paste-";

fn verify_private_dir(dir: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other("clipboard directory is not a directory"));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(std::io::Error::other("clipboard directory is owned by another user"));
    }
    if meta.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Returns (creating it, mode 0700) the directory holding per-paste download directories:
/// `$XDG_CACHE_HOME/bastion/clipboard` (or `~/.cache/...`), falling back to
/// `$XDG_RUNTIME_DIR/bastion-clipboard`. The cache dir is preferred because the runtime dir is a
/// small RAM-backed tmpfs.
pub(crate) fn download_base() -> std::io::Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(cache) = std::env::var_os("XDG_CACHE_HOME").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(cache).join("bastion/clipboard"));
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(home).join(".cache/bastion/clipboard"));
    }
    if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(run).join("bastion-clipboard"));
    }
    let mut last = std::io::Error::other("no cache or runtime directory");
    for dir in candidates {
        let attempt = std::fs::DirBuilder::new()
            .recursive(true)
            .create(&dir)
            .and_then(|()| verify_private_dir(&dir))
            .map(|()| dir);
        match attempt {
            Ok(dir) => return Ok(dir),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Removes download directories left behind by sessions that did not shut down cleanly.
/// Only entries older than a day are touched, so concurrent sessions are unaffected.
pub(crate) fn sweep_stale(base: &Path) {
    let Ok(read) = std::fs::read_dir(base) else { return };
    let now = SystemTime::now();
    for entry in read.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(DOWNLOAD_PREFIX) {
            continue;
        }
        let Ok(meta) = entry.path().symlink_metadata() else { continue };
        let old = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).is_some_and(|age| age > STALE_AFTER);
        if old && meta.is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_paths() {
        assert_eq!(sanitize_remote_path(None, "a.txt"), Ok(vec!["a.txt".to_owned()]));
        assert_eq!(
            sanitize_remote_path(Some("dir\\sub"), "r\u{e9}sum\u{e9} 1.pdf"),
            Ok(vec!["dir".to_owned(), "sub".to_owned(), "r\u{e9}sum\u{e9} 1.pdf".to_owned()])
        );
        assert_eq!(sanitize_remote_path(Some(""), "x"), Ok(vec!["x".to_owned()]));
        assert_eq!(sanitize_remote_path(None, ".hidden"), Ok(vec![".hidden".to_owned()]));
    }

    #[test]
    fn rejects_traversal() {
        assert_eq!(sanitize_remote_path(Some(".."), "x"), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(Some("a\\..\\.."), "x"), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(None, ".."), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(None, "a/../../etc/passwd"), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(None, "..."), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(None, ". ."), Err(PathRejection::Traversal));
    }

    #[test]
    fn rejects_absolute_and_unc() {
        assert_eq!(sanitize_remote_path(None, "/etc/passwd"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(None, "C:\\Windows\\x"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(None, "c:rel"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(None, "\\\\server\\share\\f"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(Some("\\\\?\\C:"), "f"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(Some("a"), "b:c"), Err(PathRejection::Colon));
    }

    #[test]
    fn rejects_device_names_nul_and_control() {
        assert_eq!(sanitize_remote_path(None, "CON"), Err(PathRejection::DeviceName));
        assert_eq!(sanitize_remote_path(None, "nul.txt"), Err(PathRejection::DeviceName));
        assert_eq!(sanitize_remote_path(Some("LPT1"), "x"), Err(PathRejection::DeviceName));
        assert_eq!(sanitize_remote_path(None, "a\0b"), Err(PathRejection::Nul));
        assert_eq!(sanitize_remote_path(None, "a\nb"), Err(PathRejection::ControlChar));
        assert_eq!(sanitize_remote_path(None, ""), Err(PathRejection::Empty));
        assert_eq!(sanitize_remote_path(Some("a\\\\b"), "c"), Err(PathRejection::Empty));
        assert!(sanitize_remote_path(None, "console.log").is_ok());
    }

    #[test]
    fn rejects_overlong_and_deep() {
        assert_eq!(sanitize_remote_path(None, &"x".repeat(256)), Err(PathRejection::TooLong));
        let deep = vec!["d"; 40].join("\\");
        assert_eq!(sanitize_remote_path(Some(&deep), "f"), Err(PathRejection::TooDeep));
    }

    #[test]
    fn private_base_dir_is_0700() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("b");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        verify_private_dir(&dir).expect("verify");
        assert_eq!(std::fs::metadata(&dir).expect("meta").mode() & 0o777, 0o700);
        let link = tmp.path().join("l");
        std::os::unix::fs::symlink(&dir, &link).expect("symlink");
        assert!(verify_private_dir(&link).is_err(), "symlinked base dir must be refused");
    }
}
