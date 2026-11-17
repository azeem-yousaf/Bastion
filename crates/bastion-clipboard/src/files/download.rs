//! Remote -> local file download state machine.
//!
//! Driven by the worker: [`Download::next`] yields the next `FileContentsRequest` to send, and
//! [`Download::on_response`] consumes its answer. Files are created with `openat(O_CREAT |
//! O_EXCL | O_NOFOLLOW)` relative to directory descriptors below a fresh private (0700)
//! directory, so a hostile file list cannot write outside it or through symlinks.

use std::collections::HashMap;
use std::fs::{File, FileTimes};
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::{Duration, Instant, UNIX_EPOCH};

use ironrdp_cliprdr::pdu::{ClipboardFileAttributes, FileContentsFlags, FileContentsRequest, FileDescriptor};
use rustix::fs::{Mode, OFlags};
use tempfile::TempDir;

use super::{DOWNLOAD_PREFIX, Limits, PathRejection, lock_download_dir, sanitize_remote_path};

/// Bytes requested per `FileContentsRequest`.
pub(crate) const CHUNK_BYTES: u32 = 1024 * 1024;

const FILETIME_UNIX_OFFSET_SECS: u64 = 11_644_473_600;

#[derive(Debug)]
pub(crate) enum DownloadError {
    NoFiles,
    TooMany(usize),
    TooLarge { size: u64, limit: u64 },
    RemoteFailed,
    Protocol(&'static str),
    Io(std::io::Error),
}

impl core::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoFiles => f.write_str("the remote file list contains no acceptable files"),
            Self::TooMany(n) => write!(f, "the remote file list has too many entries ({n})"),
            Self::TooLarge { size, limit } => {
                write!(f, "the remote files ({size} bytes) exceed the {limit} byte clipboard limit")
            }
            Self::RemoteFailed => f.write_str("the remote failed to deliver file contents"),
            Self::Protocol(why) => write!(f, "invalid file contents response: {why}"),
            Self::Io(e) => write!(f, "cannot write the downloaded file: {e}"),
        }
    }
}

impl core::error::Error for DownloadError {}

impl From<std::io::Error> for DownloadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustix::io::Errno> for DownloadError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

#[derive(Debug)]
struct Planned {
    /// Index in the remote list (the `lindex` to request).
    remote_index: i32,
    components: Vec<String>,
    is_dir: bool,
    size: Option<u64>,
    mtime: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum Outstanding {
    Size(u32),
    Range { stream_id: u32, requested: u32 },
}

#[derive(Debug)]
struct Current {
    file: File,
    size: Option<u64>,
    offset: u64,
    mtime: Option<u64>,
}

pub(crate) enum Step {
    Request(FileContentsRequest),
    /// Finished; the top-level paths to put on the local clipboard.
    Done(Vec<PathBuf>),
}

#[derive(Debug)]
pub(crate) struct Download {
    dir: TempDir,
    root: OwnedFd,
    entries: Vec<Planned>,
    next_entry: usize,
    current: Option<Current>,
    outstanding: Option<Outstanding>,
    total: u64,
    limits: Limits,
    clip_data_id: Option<u32>,
    last_activity: Instant,
}

/// A finished download on disk. Dropping it deletes the files; until then it keeps the
/// directory locked so no sweep (ours or another session's) removes it.
#[derive(Debug)]
pub(crate) struct DownloadDir {
    // Field order matters: the files go first, then the lock is released.
    _dir: TempDir,
    _lock: OwnedFd,
}

impl DownloadDir {
    #[cfg(test)]
    pub(crate) fn path(&self) -> &std::path::Path {
        self._dir.path()
    }
}

/// Counts the distinct directories and files a list would create, so nested paths cannot
/// multiply the number of inodes past the entry limit.
#[derive(Default)]
struct InodeCount {
    /// Children of each directory seen so far; index 0 is the download root.
    children: Vec<HashMap<String, usize>>,
    inodes: usize,
}

impl InodeCount {
    fn add(&mut self, components: &[String], is_dir: bool) -> usize {
        if self.children.is_empty() {
            self.children.push(HashMap::new());
        }
        let dirs = if is_dir { components } else { &components[..components.len().saturating_sub(1)] };
        let mut node = 0;
        for c in dirs {
            node = match self.children[node].get(c.as_str()) {
                Some(&child) => child,
                None => {
                    let child = self.children.len();
                    self.children.push(HashMap::new());
                    self.children[node].insert(c.clone(), child);
                    self.inodes += 1;
                    child
                }
            };
        }
        if !is_dir {
            self.inodes += 1;
        }
        self.inodes
    }
}

fn filetime_to_system(ft: u64) -> Option<std::time::SystemTime> {
    let secs = (ft / 10_000_000).checked_sub(FILETIME_UNIX_OFFSET_SECS)?;
    let nanos = u32::try_from((ft % 10_000_000) * 100).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

impl Download {
    /// Validates the remote list and creates the private download directory below `base`.
    pub(crate) fn start(
        files: &[FileDescriptor],
        clip_data_id: Option<u32>,
        base: &std::path::Path,
        limits: Limits,
    ) -> Result<Self, DownloadError> {
        if files.len() > limits.max_files {
            return Err(DownloadError::TooMany(files.len()));
        }
        let mut entries = Vec::new();
        let mut declared: u64 = 0;
        let mut inodes = InodeCount::default();
        let mut renamed = 0usize;
        for (index, f) in files.iter().enumerate() {
            let components = match sanitize_remote_path(f.relative_path.as_deref(), &f.name) {
                Ok(c) => c,
                Err(why) => {
                    log_rejection(why);
                    continue;
                }
            };
            let is_dir = f.attributes.is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY));
            // Parent directories are created implicitly, so they count too: 10,000 entries with
            // distinct 33-deep paths would otherwise create 330,000 directories.
            let created = inodes.add(&components, is_dir);
            if created > limits.max_files {
                return Err(DownloadError::TooMany(created));
            }
            if components.last().is_some_and(|last| !f.name.ends_with(last.as_str())) {
                renamed += 1;
            }
            if !is_dir && let Some(size) = f.file_size {
                declared = declared.saturating_add(size);
                if size > limits.max_total_bytes || declared > limits.max_total_bytes {
                    return Err(DownloadError::TooLarge { size: declared, limit: limits.max_total_bytes });
                }
            }
            let Ok(remote_index) = i32::try_from(index) else { break };
            entries.push(Planned { remote_index, components, is_dir, size: f.file_size, mtime: f.last_write_time });
        }
        if entries.is_empty() {
            return Err(DownloadError::NoFiles);
        }
        if renamed > 0 {
            tracing::info!(renamed, "Renamed hidden or deceptive file names from the remote clipboard");
        }
        let dir = tempfile::Builder::new()
            .prefix(DOWNLOAD_PREFIX)
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(base)?;
        let root = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // Held for as long as the directory exists; see `files::sweep_stale`.
        if !lock_download_dir(&root) {
            tracing::debug!("Could not lock the clipboard download directory");
        }
        Ok(Self {
            dir,
            root,
            entries,
            next_entry: 0,
            current: None,
            outstanding: None,
            total: 0,
            limits,
            clip_data_id,
            last_activity: Instant::now(),
        })
    }

    pub(crate) fn last_activity(&self) -> Instant {
        self.last_activity
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    pub(crate) fn into_dir(self) -> DownloadDir {
        DownloadDir { _dir: self.dir, _lock: self.root }
    }

    /// Opens (creating as needed) the directory for `components` below the root, never
    /// following symlinks.
    fn open_dir(&self, components: &[String]) -> std::io::Result<OwnedFd> {
        let mut cur =
            rustix::fs::openat(&self.root, ".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        for c in components {
            match rustix::fs::mkdirat(&cur, c.as_str(), Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            cur = rustix::fs::openat(
                &cur,
                c.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
        }
        Ok(cur)
    }

    fn request(&self, stream_id: u32, flags: FileContentsFlags, position: u64, size: u32) -> FileContentsRequest {
        let index = self.entries.get(self.next_entry.wrapping_sub(1)).map_or(0, |e| e.remote_index);
        FileContentsRequest { stream_id, index, flags, position, requested_size: size, data_id: self.clip_data_id }
    }

    fn finish_current(&mut self) -> std::io::Result<()> {
        if let Some(cur) = self.current.take() {
            if let Some(t) = cur.mtime.and_then(filetime_to_system) {
                let _ = cur.file.set_times(FileTimes::new().set_modified(t));
            }
            cur.file.sync_data().ok();
        }
        Ok(())
    }

    /// Advances the transfer; `stream_id` is used if a request is needed.
    pub(crate) fn next(&mut self, stream_id: u32) -> Result<Step, DownloadError> {
        if self.outstanding.is_some() {
            return Err(DownloadError::Protocol("request already outstanding"));
        }
        loop {
            if let Some(cur) = &self.current {
                match cur.size {
                    None => {
                        self.outstanding = Some(Outstanding::Size(stream_id));
                        return Ok(Step::Request(self.request(stream_id, FileContentsFlags::SIZE, 0, 8)));
                    }
                    Some(size) if cur.offset < size => {
                        let want =
                            u32::try_from((size - cur.offset).min(u64::from(CHUNK_BYTES))).unwrap_or(CHUNK_BYTES);
                        let position = cur.offset;
                        self.outstanding = Some(Outstanding::Range { stream_id, requested: want });
                        return Ok(Step::Request(self.request(stream_id, FileContentsFlags::RANGE, position, want)));
                    }
                    Some(_) => self.finish_current()?,
                }
                continue;
            }
            let Some(entry) = self.entries.get(self.next_entry) else {
                return Ok(Step::Done(self.top_level()));
            };
            self.next_entry += 1;
            let (parents, name) = entry.components.split_at(entry.components.len() - 1);
            let parent = self.open_dir(parents)?;
            if entry.is_dir {
                drop(self.open_dir(&entry.components)?);
                continue;
            }
            let fd = match rustix::fs::openat(
                &parent,
                name[0].as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::EXIST) => {
                    tracing::warn!("Skipping a duplicate entry in the remote file list");
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            self.current = Some(Current { file: File::from(fd), size: entry.size, offset: 0, mtime: entry.mtime });
        }
    }

    /// Consumes a response. Returns `Ok(false)` if `stream_id` is not ours (ignored).
    pub(crate) fn on_response(&mut self, stream_id: u32, data: Option<&[u8]>) -> Result<bool, DownloadError> {
        let id = match self.outstanding {
            Some(Outstanding::Size(id) | Outstanding::Range { stream_id: id, .. }) => id,
            None => return Ok(false),
        };
        if id != stream_id {
            return Ok(false);
        }
        let outstanding = self.outstanding.take();
        self.last_activity = Instant::now();
        let data = data.ok_or(DownloadError::RemoteFailed)?;
        let cur = self.current.as_mut().ok_or(DownloadError::Protocol("no file in progress"))?;
        match outstanding {
            Some(Outstanding::Size(_)) => {
                let bytes: [u8; 8] = data.try_into().map_err(|_| DownloadError::Protocol("size is not 8 bytes"))?;
                let size = u64::from_le_bytes(bytes);
                let total = self.total.saturating_add(size);
                if size > self.limits.max_total_bytes || total > self.limits.max_total_bytes {
                    return Err(DownloadError::TooLarge { size: total, limit: self.limits.max_total_bytes });
                }
                cur.size = Some(size);
            }
            Some(Outstanding::Range { requested, .. }) => {
                if data.len() > usize::try_from(requested).unwrap_or(usize::MAX) {
                    return Err(DownloadError::Protocol("more data than requested"));
                }
                if data.is_empty() {
                    // Remote reached EOF early (file shrank): keep what we have.
                    cur.size = Some(cur.offset);
                    return Ok(true);
                }
                let len = data.len() as u64;
                let total = self.total.saturating_add(len);
                if total > self.limits.max_total_bytes {
                    return Err(DownloadError::TooLarge { size: total, limit: self.limits.max_total_bytes });
                }
                cur.file.write_all(data)?;
                cur.offset += len;
                self.total = total;
            }
            None => {}
        }
        Ok(true)
    }

    /// Top-level items (what the user copied), as absolute paths.
    fn top_level(&self) -> Vec<PathBuf> {
        let mut seen: Vec<&str> = Vec::new();
        for e in &self.entries {
            let first = e.components[0].as_str();
            if !seen.contains(&first) && self.dir.path().join(first).exists() {
                seen.push(first);
            }
        }
        seen.into_iter().map(|c| self.dir.path().join(c)).collect()
    }

    pub(crate) fn bytes_written(&self) -> u64 {
        self.total
    }
}

fn log_rejection(why: PathRejection) {
    tracing::warn!(reason = ?why, "Rejected an unsafe file name in the remote file list");
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn limits(max: u64) -> Limits {
        Limits { max_total_bytes: max, max_files: 100 }
    }

    fn file(name: &str, rel: Option<&str>, size: Option<u64>) -> FileDescriptor {
        let mut d = FileDescriptor::new(name).with_attributes(ClipboardFileAttributes::ARCHIVE);
        if let Some(s) = size {
            d = d.with_file_size(s);
        }
        if let Some(r) = rel {
            d = d.with_relative_path(r);
        }
        d
    }

    fn dir(name: &str, rel: Option<&str>) -> FileDescriptor {
        let mut d = FileDescriptor::new(name).with_attributes(ClipboardFileAttributes::DIRECTORY);
        if let Some(r) = rel {
            d = d.with_relative_path(r);
        }
        d
    }

    /// Plays the remote side: serves `contents[index]`.
    fn run(dl: &mut Download, contents: &[Vec<u8>]) -> Result<Vec<PathBuf>, DownloadError> {
        let mut stream = 1;
        loop {
            match dl.next(stream)? {
                Step::Done(paths) => return Ok(paths),
                Step::Request(req) => {
                    let data = &contents[usize::try_from(req.index).expect("index")];
                    let reply = if req.flags.contains(FileContentsFlags::SIZE) {
                        (data.len() as u64).to_le_bytes().to_vec()
                    } else {
                        let start = usize::try_from(req.position).expect("pos").min(data.len());
                        let end = (start + req.requested_size as usize).min(data.len());
                        data[start..end].to_vec()
                    };
                    assert!(dl.on_response(req.stream_id, Some(&reply))?);
                }
            }
            stream += 1;
        }
    }

    #[test]
    fn downloads_tree_with_sizes_and_unknown_size() {
        let base = tempfile::tempdir().expect("tmp");
        let big: Vec<u8> = (0..(CHUNK_BYTES as usize * 2 + 17)).map(|i| (i % 251) as u8).collect();
        let files = vec![
            dir("folder", None),
            file("big.bin", Some("folder"), Some(big.len() as u64)),
            dir("inner", Some("folder")),
            file("\u{65e5}\u{672c} file.txt", Some("folder\\inner"), None),
            file("top.txt", None, Some(3)),
            file("empty", None, Some(0)),
        ];
        let contents = vec![vec![], big.clone(), vec![], b"unknown size".to_vec(), b"top".to_vec(), vec![]];
        let mut dl = Download::start(&files, Some(7), base.path(), limits(64 << 20)).expect("start");
        assert_eq!(std::fs::metadata(dl.path()).expect("meta").permissions().mode() & 0o777, 0o700);
        let paths = run(&mut dl, &contents).expect("download");
        let root = dl.path().to_owned();
        assert_eq!(paths, vec![root.join("folder"), root.join("top.txt"), root.join("empty")]);
        assert_eq!(std::fs::read(root.join("folder/big.bin")).expect("read"), big);
        assert_eq!(std::fs::read(root.join("folder/inner/\u{65e5}\u{672c} file.txt")).expect("read"), b"unknown size");
        assert_eq!(std::fs::read(root.join("top.txt")).expect("read"), b"top");
        assert_eq!(std::fs::read(root.join("empty")).expect("read"), b"");
        assert_eq!(dl.bytes_written(), big.len() as u64 + 12 + 3);
        let tmp = dl.into_dir();
        let kept = tmp.path().to_owned();
        drop(tmp);
        assert!(!kept.exists(), "dropping the download removes its files");
    }

    #[test]
    fn requests_carry_lock_id_and_index() {
        let base = tempfile::tempdir().expect("tmp");
        let files = vec![file("bad/../x", None, Some(1)), file("ok", None, Some(4))];
        let mut dl = Download::start(&files, Some(42), base.path(), limits(100)).expect("start");
        let Step::Request(req) = dl.next(9).expect("next") else { panic!("expected request") };
        assert_eq!((req.index, req.data_id, req.position, req.requested_size), (1, Some(42), 0, 4));
        assert!(req.flags.contains(FileContentsFlags::RANGE));
        assert!(!dl.on_response(8, Some(b"nope")).expect("foreign stream"), "other stream ids are ignored");
        assert!(dl.on_response(9, Some(b"data")).expect("ours"));
    }

    #[test]
    fn declared_size_over_limit_is_refused_up_front() {
        let base = tempfile::tempdir().expect("tmp");
        let files = vec![file("a", None, Some(60)), file("b", None, Some(60))];
        assert!(matches!(Download::start(&files, None, base.path(), limits(100)), Err(DownloadError::TooLarge { .. })));
        let huge = vec![file("a", None, Some(u64::MAX))];
        assert!(matches!(Download::start(&huge, None, base.path(), limits(100)), Err(DownloadError::TooLarge { .. })));
        assert_eq!(std::fs::read_dir(base.path()).expect("ls").count(), 0, "nothing created");
    }

    #[test]
    fn size_response_over_limit_is_refused() {
        let base = tempfile::tempdir().expect("tmp");
        let mut dl = Download::start(&[file("a", None, None)], None, base.path(), limits(100)).expect("start");
        let Step::Request(req) = dl.next(1).expect("next") else { panic!() };
        assert!(req.flags.contains(FileContentsFlags::SIZE));
        assert!(matches!(dl.on_response(1, Some(&1000u64.to_le_bytes())), Err(DownloadError::TooLarge { .. })));
    }

    #[test]
    fn oversized_or_failed_range_responses_abort() {
        let base = tempfile::tempdir().expect("tmp");
        let mut dl = Download::start(&[file("a", None, Some(4))], None, base.path(), limits(100)).expect("start");
        let Step::Request(req) = dl.next(1).expect("next") else { panic!() };
        assert!(matches!(dl.on_response(req.stream_id, Some(b"too long")), Err(DownloadError::Protocol(_))));

        let mut dl = Download::start(&[file("a", None, Some(4))], None, base.path(), limits(100)).expect("start");
        let Step::Request(req) = dl.next(1).expect("next") else { panic!() };
        assert!(matches!(dl.on_response(req.stream_id, None), Err(DownloadError::RemoteFailed)));
    }

    #[test]
    fn hostile_names_never_escape_root() {
        let base = tempfile::tempdir().expect("tmp");
        let files = vec![
            file("passwd", Some("..\\..\\etc"), Some(1)),
            file("/abs", None, Some(1)),
            file("CON", None, Some(1)),
            file("ok.txt", None, Some(2)),
        ];
        let mut dl = Download::start(&files, None, base.path(), limits(100)).expect("start");
        let contents = vec![b"x".to_vec(), b"x".to_vec(), b"x".to_vec(), b"ok".to_vec()];
        let paths = run(&mut dl, &contents).expect("download");
        assert_eq!(paths, vec![dl.path().join("ok.txt")]);
        let listing: Vec<_> = std::fs::read_dir(dl.path()).expect("ls").map(|e| e.expect("e").file_name()).collect();
        assert_eq!(listing, vec![std::ffi::OsString::from("ok.txt")]);
        assert_eq!(std::fs::read_dir(base.path()).expect("ls").count(), 1, "only the private dir in base");
    }

    #[test]
    fn duplicate_names_are_skipped_and_symlinks_not_followed() {
        let base = tempfile::tempdir().expect("tmp");
        let files = vec![file("a", None, Some(1)), file("a", None, Some(1)), file("b", Some("a"), Some(1))];
        let mut dl = Download::start(&files, None, base.path(), limits(100)).expect("start");
        // "a" is a file, so creating "a/b" must fail (not follow anything).
        let contents = vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()];
        assert!(run(&mut dl, &contents).is_err());
        assert_eq!(std::fs::read(dl.path().join("a")).expect("read"), b"1");
    }

    #[test]
    fn too_many_entries() {
        let base = tempfile::tempdir().expect("tmp");
        let files: Vec<_> = (0..5).map(|i| file(&format!("f{i}"), None, Some(1))).collect();
        let l = Limits { max_total_bytes: 100, max_files: 4 };
        assert!(matches!(Download::start(&files, None, base.path(), l), Err(DownloadError::TooMany(5))));
        assert!(matches!(Download::start(&[], None, base.path(), limits(1)), Err(DownloadError::NoFiles)));
    }

    #[test]
    fn implicit_directories_count_against_the_entry_limit() {
        let base = tempfile::tempdir().expect("tmp");
        // 20 entries, each below its own 5-deep directory chain: 100 directories + 20 files.
        let files: Vec<_> =
            (0..20).map(|i| file("f", Some(&format!("a{i}\\b{i}\\c{i}\\d{i}\\e{i}")), Some(0))).collect();
        assert!(matches!(
            Download::start(&files, None, base.path(), limits(1 << 20)),
            Err(DownloadError::TooMany(n)) if n > 100
        ));
        let dirs: Vec<_> = (0..30).map(|i| dir(&format!("leaf{i}"), Some(&format!("x{i}\\y{i}\\z{i}")))).collect();
        assert!(matches!(Download::start(&dirs, None, base.path(), limits(1 << 20)), Err(DownloadError::TooMany(_))));
        assert_eq!(std::fs::read_dir(base.path()).expect("ls").count(), 0, "nothing created");

        // Shared parents are counted once: 1 + 1 directories and 98 files fit in 100.
        let mut shared = vec![dir("top", None), dir("sub", Some("top"))];
        shared.extend((0..98).map(|i| file(&format!("f{i}"), Some("top\\sub"), Some(0))));
        let mut dl = Download::start(&shared, None, base.path(), limits(1 << 20)).expect("start");
        let contents = vec![Vec::new(); shared.len()];
        assert_eq!(run(&mut dl, &contents).expect("download"), vec![dl.path().join("top")]);
        assert_eq!(std::fs::read_dir(dl.path().join("top/sub")).expect("ls").count(), 98);
    }

    #[test]
    fn hidden_names_arrive_under_visible_names() {
        let base = tempfile::tempdir().expect("tmp");
        let files = vec![
            file("report.docx", None, Some(2)),
            file(".bash_profile", None, Some(4)),
            dir(".ssh", None),
            file("authorized_keys", Some(".ssh"), Some(3)),
        ];
        let contents = vec![b"ok".to_vec(), b"evil".to_vec(), vec![], b"key".to_vec()];
        let mut dl = Download::start(&files, None, base.path(), limits(100)).expect("start");
        let paths = run(&mut dl, &contents).expect("download");
        let root = dl.path().to_owned();
        assert_eq!(paths, vec![root.join("report.docx"), root.join("_bash_profile"), root.join("_ssh")]);
        assert_eq!(std::fs::read(root.join("_bash_profile")).expect("read"), b"evil", "contents still arrive");
        assert_eq!(std::fs::read(root.join("_ssh/authorized_keys")).expect("read"), b"key");
        let hidden: Vec<_> = std::fs::read_dir(&root)
            .expect("ls")
            .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(hidden.is_empty(), "no hidden entry may be created: {hidden:?}");
    }

    #[test]
    fn download_directory_stays_locked_until_dropped() {
        let base = tempfile::tempdir().expect("tmp");
        let mut dl = Download::start(&[file("a", None, Some(1))], None, base.path(), limits(100)).expect("start");
        let path = dl.path().to_owned();
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let set_old = |p: &std::path::Path| File::open(p).expect("open").set_modified(old).expect("mtime");
        set_old(&path);
        super::super::sweep_stale(base.path());
        assert!(path.exists(), "a download in progress survives a sweep");
        run(&mut dl, &[b"x".to_vec()]).expect("download");
        let kept = dl.into_dir();
        set_old(&path);
        super::super::sweep_stale(base.path());
        assert!(path.join("a").exists(), "a finished download still on the clipboard survives a sweep");
        drop(kept);
        assert!(!path.exists());
    }

    #[test]
    fn filetime_conversion() {
        let t = filetime_to_system(FILETIME_UNIX_OFFSET_SECS * 10_000_000 + 15).expect("time");
        assert_eq!(t.duration_since(UNIX_EPOCH).expect("since").as_nanos(), 1500);
        assert!(filetime_to_system(0).is_none());
    }
}
