//! File clipboard support: local file lists (upload) and remote downloads into a private
//! temporary directory.

pub(crate) mod download;
pub(crate) mod local;

use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use rustix::fs::{FlockOperation, Mode, OFlags};

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

/// Characters that reorder or hide text when a name is displayed (bidi marks, embeddings,
/// overrides and isolates). They let `exe.txt` be shown for a name that really ends in `.exe`.
fn is_display_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Makes one already validated component safe to show and to paste anywhere:
///
/// * a leading `.` becomes `_`, so nothing the server sends lands as a hidden file. The user
///   cannot see what is about to be pasted, and a paste into the home directory must never
///   create `.bash_profile`, `.ssh/authorized_keys` and the like. The contents still arrive,
///   under a visible name;
/// * bidi/format control characters become `_`.
fn defuse_component(component: &str) -> String {
    let mut out: String = component.chars().map(|c| if is_display_control(c) { '_' } else { c }).collect();
    if out.starts_with('.') {
        out.replace_range(..1, "_");
    }
    out
}

/// Validates a remote `relative_path` + `name` pair (as delivered by `Cliprdr`, which already
/// sanitized it once) and returns the path components to create below the download root.
///
/// This is a second, strict line of defence: anything that could leave the download directory
/// is rejected outright instead of being repaired. Names that are merely deceptive (hidden
/// files, bidi controls) are kept but renamed, see [`defuse_component`].
pub(crate) fn sanitize_remote_path(relative: Option<&str>, name: &str) -> Result<Vec<String>, PathRejection> {
    let joined = remote_joined(relative, name);
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
        out.push(defuse_component(component));
        if out.len() > MAX_REMOTE_DEPTH {
            return Err(PathRejection::TooDeep);
        }
    }
    Ok(out)
}

fn remote_joined(relative: Option<&str>, name: &str) -> String {
    match relative {
        Some(r) if !r.is_empty() => format!("{r}\\{name}"),
        _ => name.to_owned(),
    }
}

/// The remote path's components as sent (before [`defuse_component`]); for a path that
/// [`sanitize_remote_path`] accepted they correspond one to one with its result.
pub(crate) fn raw_remote_components(relative: Option<&str>, name: &str) -> Vec<String> {
    remote_joined(relative, name).split(['\\', '/']).map(str::to_owned).collect()
}

/// `name` with ` (n)` before its extension: `_x (1)`, `report (2).pdf`. `None` if too long.
pub(crate) fn numbered_name(name: &str, n: usize) -> Option<String> {
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    let out = format!("{stem} ({n}){ext}");
    (out.len() <= MAX_COMPONENT_BYTES).then_some(out)
}

pub(crate) const DOWNLOAD_PREFIX: &str = "paste-";
/// A download directory this young is never swept: its owner may not have locked it yet.
const SWEEP_GRACE: Duration = Duration::from_secs(10);

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

/// Where download directories may live, best first (nothing is created).
fn base_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(cache) = std::env::var_os("XDG_CACHE_HOME").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(cache).join("bastion/clipboard"));
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(home).join(".cache/bastion/clipboard"));
    }
    if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| Path::new(v).is_absolute()) {
        candidates.push(PathBuf::from(run).join("bastion-clipboard"));
    }
    candidates
}

/// Returns (creating it, mode 0700) the directory holding per-paste download directories:
/// `$XDG_CACHE_HOME/bastion/clipboard` (or `~/.cache/...`), falling back to
/// `$XDG_RUNTIME_DIR/bastion-clipboard`. The cache dir is preferred because the runtime dir is a
/// small RAM-backed tmpfs.
pub(crate) fn download_base() -> std::io::Result<PathBuf> {
    let mut last = std::io::Error::other("no cache or runtime directory");
    for dir in base_candidates() {
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

/// Download bases used by any session of this process (sessions in tests use their own).
static BASES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Records `base` as a place this process downloads remote files to.
pub(crate) fn register_base(base: &Path) {
    let mut bases = BASES.lock().unwrap_or_else(PoisonError::into_inner);
    if !bases.iter().any(|b| b == base) {
        bases.push(base.to_owned());
    }
}

/// Whether every path is a file some Bastion session downloaded from a remote clipboard, in
/// this process (any session, not only the caller's) or in another one using the default
/// directories. Such files must not be offered to a remote again.
pub(crate) fn are_downloads(paths: &[PathBuf]) -> bool {
    if paths.is_empty() {
        return false;
    }
    let mut bases = base_candidates();
    bases.extend(BASES.lock().unwrap_or_else(PoisonError::into_inner).iter().cloned());
    paths.iter().all(|p| bases.iter().any(|base| p.starts_with(base)))
}

/// Marks an open download directory as in use by a live session. The lock belongs to the open
/// file description, so the kernel drops it when the descriptor is closed, including when the
/// process is killed. Returns whether the lock was taken.
pub(crate) fn lock_download_dir(dir: &OwnedFd) -> bool {
    rustix::fs::flock(dir, FlockOperation::NonBlockingLockExclusive).is_ok()
}

/// Removes download directories whose session is gone (crash, kill, slow shutdown), whatever
/// their age: they hold remote files in clear. A directory still locked by a live session, in
/// this process or another, is never touched, however old it is.
pub(crate) fn sweep_stale(base: &Path) {
    let Ok(read) = std::fs::read_dir(base) else { return };
    let now = SystemTime::now();
    for entry in read.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(DOWNLOAD_PREFIX) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = path.symlink_metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        // Just created: the owner locks it right after creating it.
        let young = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).is_some_and(|age| age < SWEEP_GRACE);
        if young {
            continue;
        }
        let Ok(dir) = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };
        // Held (or locking is unsupported here): leave it alone.
        if !lock_download_dir(&dir) {
            continue;
        }
        if let Err(error) = std::fs::remove_dir_all(&path) {
            tracing::debug!(%error, "Could not remove an abandoned clipboard download directory");
        } else {
            tracing::info!("Removed a clipboard download directory left behind by an earlier session");
        }
    }
}

/// Sweeps the default download locations. Run when a session's clipboard starts, so files left
/// by a crashed session do not wait for the next file paste. Never creates anything.
pub(crate) fn sweep_at_startup() {
    for base in base_candidates() {
        let ours =
            std::fs::symlink_metadata(&base).is_ok_and(|m| m.is_dir() && m.uid() == rustix::process::getuid().as_raw());
        if ours {
            sweep_stale(&base);
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
    }

    #[test]
    fn hidden_names_are_made_visible() {
        assert_eq!(sanitize_remote_path(None, ".hidden"), Ok(vec!["_hidden".to_owned()]));
        assert_eq!(sanitize_remote_path(None, ".bash_profile"), Ok(vec!["_bash_profile".to_owned()]));
        assert_eq!(
            sanitize_remote_path(Some(".ssh"), "authorized_keys"),
            Ok(vec!["_ssh".to_owned(), "authorized_keys".to_owned()])
        );
        assert_eq!(
            sanitize_remote_path(Some("a\\.config\\autostart"), ".x.desktop"),
            Ok(vec!["a".to_owned(), "_config".to_owned(), "autostart".to_owned(), "_x.desktop".to_owned()])
        );
        assert_eq!(sanitize_remote_path(None, "..rc"), Ok(vec!["_.rc".to_owned()]));
        // Forward slashes are separators too, so they cannot smuggle a hidden component.
        assert_eq!(sanitize_remote_path(None, "a/.b"), Ok(vec!["a".to_owned(), "_b".to_owned()]));
        // Dots elsewhere are ordinary.
        assert_eq!(sanitize_remote_path(None, "a.tar.gz"), Ok(vec!["a.tar.gz".to_owned()]));
        for name in [".", "..", "...", ". ."] {
            assert_eq!(sanitize_remote_path(None, name), Err(PathRejection::Traversal), "{name:?} is not renamed");
        }
    }

    #[test]
    fn display_controls_are_replaced() {
        // "photo<RLO>gpj.exe" renders as "photoexe.jpg".
        assert_eq!(sanitize_remote_path(None, "photo\u{202E}gpj.exe"), Ok(vec!["photo_gpj.exe".to_owned()]));
        assert_eq!(sanitize_remote_path(None, "a\u{200F}b\u{2067}c\u{061C}"), Ok(vec!["a_b_c_".to_owned()]));
        // A name hidden behind a format character is still hidden once that is gone.
        assert_eq!(sanitize_remote_path(None, "\u{200E}.profile"), Ok(vec!["_.profile".to_owned()]));
        for c in ['\u{200E}', '\u{202A}', '\u{202D}', '\u{2066}', '\u{2069}'] {
            let got = sanitize_remote_path(None, &format!("x{c}y")).expect("accepted");
            assert_eq!(got, vec!["x_y".to_owned()]);
        }
    }

    #[test]
    fn separators_nul_and_length_stay_neutralised() {
        // Every separator spelling splits; no component can contain one.
        let got = sanitize_remote_path(Some("a/b\\c"), "d").expect("accepted");
        assert!(got.iter().all(|c| !c.contains(['/', '\\'])), "{got:?}");
        assert_eq!(sanitize_remote_path(Some("a\0"), "b"), Err(PathRejection::Nul));
        assert_eq!(sanitize_remote_path(Some("~"), "x"), Ok(vec!["~".to_owned(), "x".to_owned()]));
        assert_eq!(sanitize_remote_path(None, "//etc/passwd"), Err(PathRejection::Absolute));
        assert_eq!(sanitize_remote_path(None, "a//b"), Err(PathRejection::Empty));
        assert_eq!(sanitize_remote_path(Some("a/"), "b"), Err(PathRejection::Empty));
        assert_eq!(sanitize_remote_path(Some("a\\.."), "b"), Err(PathRejection::Traversal));
        assert_eq!(sanitize_remote_path(Some("a\\.\\b"), "c"), Err(PathRejection::Traversal));
        // 255 bytes is NAME_MAX; multi-byte names are measured in bytes, and renaming never grows a name.
        assert!(sanitize_remote_path(None, &"x".repeat(255)).is_ok());
        assert_eq!(sanitize_remote_path(None, &"\u{e9}".repeat(128)), Err(PathRejection::TooLong));
        let hidden = format!(".{}", "x".repeat(254));
        assert_eq!(sanitize_remote_path(None, &hidden).expect("accepted")[0].len(), 255);
        assert_eq!(sanitize_remote_path(Some(&"x".repeat(256)), "f"), Err(PathRejection::TooLong));
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

    fn age(dir: &Path, secs: u64) {
        let then = SystemTime::now() - Duration::from_secs(secs);
        std::fs::File::open(dir).expect("open dir").set_modified(then).expect("set mtime");
    }

    fn open_dir(dir: &Path) -> OwnedFd {
        rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).expect("open")
    }

    #[test]
    fn sweep_removes_abandoned_directories_and_spares_live_ones() {
        let base = tempfile::tempdir().expect("tmp");
        let mk = |name: &str| {
            let dir = base.path().join(name);
            std::fs::create_dir(&dir).expect("mkdir");
            std::fs::write(dir.join("secret.txt"), b"remote data").expect("write");
            dir
        };
        // Left by a dead session a minute ago: no lock.
        let abandoned = mk("paste-dead");
        age(&abandoned, 60);
        // A live session's download from two days ago (still offered on the clipboard).
        let live = mk("paste-live");
        age(&live, 2 * 24 * 3600);
        let lock = open_dir(&live);
        assert!(lock_download_dir(&lock));
        // Created this instant: its owner has not locked it yet.
        let fresh = mk("paste-fresh");
        // Not ours to judge.
        let other = mk("other");
        age(&other, 3 * 24 * 3600);
        let file = base.path().join("paste-file");
        std::fs::write(&file, b"x").expect("write");

        sweep_stale(base.path());
        assert!(!abandoned.exists(), "abandoned downloads are removed without waiting a day");
        assert!(live.join("secret.txt").exists(), "a locked directory is never removed, however old");
        assert!(fresh.exists());
        assert!(other.exists());
        assert!(file.exists());

        // Once the owner is gone (descriptor closed, as the kernel does for a killed process)...
        drop(lock);
        sweep_stale(base.path());
        assert!(!live.exists(), "...the next sweep removes it");
    }

    #[test]
    fn downloads_are_recognised_across_sessions() {
        let a = tempfile::tempdir().expect("tmp");
        let elsewhere = tempfile::tempdir().expect("tmp");
        let file = a.path().join("paste-1/report.docx");
        assert!(!are_downloads(std::slice::from_ref(&file)));
        register_base(a.path());
        register_base(a.path());
        assert!(are_downloads(std::slice::from_ref(&file)));
        assert!(!are_downloads(&[file, elsewhere.path().join("mine.txt")]), "all paths must be downloads");
        assert!(!are_downloads(&[]));
    }
}
