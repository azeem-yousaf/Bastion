//! Local -> remote file copy: turns local paths into a `FileGroupDescriptorW` list and serves
//! `FileContentsRequest`s from it.

use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use ironrdp_cliprdr::pdu::{ClipboardFileAttributes, FileDescriptor};
use rustix::fs::{Mode, OFlags};

use super::Limits;

/// Max UTF-16 units of `relative\name` on the wire (260 incl. NUL); `Cliprdr::initiate_file_copy`
/// silently drops longer entries, which would shift every later index, so we drop them first.
const MAX_WIRE_NAME_UNITS: usize = 259;
/// Max directory nesting below a copied directory.
const MAX_DEPTH: usize = 32;

/// Seconds between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_OFFSET_SECS: u64 = 11_644_473_600;

#[derive(Debug, Clone)]
struct LocalEntry {
    path: PathBuf,
    is_dir: bool,
    size: u64,
    dev: u64,
    ino: u64,
}

/// A snapshot of the files the local user copied, indexed exactly like the descriptor list sent
/// to the server.
#[derive(Debug, Clone)]
pub(crate) struct LocalFileList {
    entries: Vec<LocalEntry>,
    descriptors: Vec<FileDescriptor>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListError {
    Empty,
    TooMany(usize),
    TooLarge { total: u64, limit: u64 },
}

impl core::fmt::Display for ListError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("no readable local files"),
            Self::TooMany(n) => write!(f, "too many files ({n}+)"),
            Self::TooLarge { total, limit } => write!(f, "files total {total} bytes, over the {limit} byte limit"),
        }
    }
}

/// Characters Windows does not allow in file names are replaced so Explorer can create the file.
fn windows_safe_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c < ' ' { '_' } else { c })
        .collect();
    if s.ends_with(['.', ' ']) {
        s.pop();
        s.push('_');
    }
    if s.is_empty() { "_".to_owned() } else { s }
}

fn filetime(meta: &Metadata) -> Option<u64> {
    let since = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    let secs = since.as_secs().checked_add(FILETIME_UNIX_OFFSET_SECS)?;
    secs.checked_mul(10_000_000)?.checked_add(u64::from(since.subsec_nanos() / 100))
}

fn wire_units(relative: &str, name: &str) -> usize {
    let name_units = name.encode_utf16().count();
    if relative.is_empty() { name_units } else { relative.encode_utf16().count() + 1 + name_units }
}

struct Builder<'a> {
    limits: &'a Limits,
    entries: Vec<LocalEntry>,
    descriptors: Vec<FileDescriptor>,
    total: u64,
}

impl Builder<'_> {
    fn push(&mut self, path: &Path, meta: &Metadata, relative: &str, name: &str) -> Result<bool, ListError> {
        if wire_units(relative, name) > MAX_WIRE_NAME_UNITS {
            tracing::debug!("Skipping a local file whose path is too long for CLIPRDR");
            return Ok(false);
        }
        if self.entries.len() >= self.limits.max_files {
            return Err(ListError::TooMany(self.entries.len()));
        }
        let is_dir = meta.is_dir();
        let size = if is_dir { 0 } else { meta.len() };
        self.total = self.total.saturating_add(size);
        if self.total > self.limits.max_total_bytes {
            return Err(ListError::TooLarge { total: self.total, limit: self.limits.max_total_bytes });
        }
        let attributes = if is_dir { ClipboardFileAttributes::DIRECTORY } else { ClipboardFileAttributes::ARCHIVE };
        let mut desc = FileDescriptor::new(name).with_attributes(attributes).with_file_size(size);
        if let Some(t) = filetime(meta) {
            desc = desc.with_last_write_time(t);
        }
        if !relative.is_empty() {
            desc = desc.with_relative_path(relative);
        }
        self.descriptors.push(desc);
        self.entries.push(LocalEntry { path: path.to_owned(), is_dir, size, dev: meta.dev(), ino: meta.ino() });
        Ok(true)
    }

    fn walk(&mut self, dir: &Path, relative: &str, depth: usize) -> Result<(), ListError> {
        if depth > MAX_DEPTH {
            return Ok(());
        }
        let Ok(read) = std::fs::read_dir(dir) else { return Ok(()) };
        let mut children: Vec<_> = read.filter_map(Result::ok).collect();
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            // Never follow symlinks inside a copied directory (loops, escaping the tree).
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if !(meta.is_file() || meta.is_dir()) {
                continue;
            }
            let name = windows_safe_name(&child.file_name().to_string_lossy());
            if self.push(&path, &meta, relative, &name)? && meta.is_dir() {
                let sub = format!("{relative}\\{name}");
                self.walk(&path, &sub, depth + 1)?;
            }
        }
        Ok(())
    }
}

impl LocalFileList {
    /// Builds the list for the given top-level paths (as found in a local `text/uri-list`).
    ///
    /// Directories are expanded recursively (symlinks below a directory are skipped). Top-level
    /// symlinks are resolved, since the user selected them explicitly.
    pub(crate) fn build(paths: &[PathBuf], limits: &Limits) -> Result<Self, ListError> {
        let mut b = Builder { limits, entries: Vec::new(), descriptors: Vec::new(), total: 0 };
        for p in paths {
            let Ok(path) = std::fs::canonicalize(p) else { continue };
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if !(meta.is_file() || meta.is_dir()) {
                continue;
            }
            let Some(name) = path.file_name() else { continue };
            let name = windows_safe_name(&name.to_string_lossy());
            if b.push(&path, &meta, "", &name)? && meta.is_dir() {
                b.walk(&path, &name, 1)?;
            }
        }
        if b.entries.is_empty() {
            return Err(ListError::Empty);
        }
        Ok(Self { entries: b.entries, descriptors: b.descriptors })
    }

    pub(crate) fn descriptors(&self) -> &[FileDescriptor] {
        &self.descriptors
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether every path is inside `root` (used to detect our own downloads being re-copied).
    pub(crate) fn top_level_within(paths: &[PathBuf], root: &Path) -> bool {
        !paths.is_empty() && paths.iter().all(|p| p.starts_with(root))
    }

    /// Size advertised for entry `index`.
    pub(crate) fn size(&self, index: usize) -> Option<u64> {
        self.entries.get(index).map(|e| e.size)
    }

    /// Reads up to `len` bytes at `position` from entry `index`, never past the advertised size.
    ///
    /// The file is opened with `O_NOFOLLOW` and must still be the same inode that was listed, so
    /// swapping it for a symlink or another file after the copy is refused.
    pub(crate) fn read_range(&self, index: usize, position: u64, len: u32) -> std::io::Result<Vec<u8>> {
        let entry = self.entries.get(index).ok_or_else(|| std::io::Error::other("file index out of range"))?;
        if entry.is_dir {
            return Err(std::io::Error::other("cannot read a directory"));
        }
        let end = position.saturating_add(u64::from(len)).min(entry.size);
        if position >= end {
            return Ok(Vec::new());
        }
        let fd = rustix::fs::open(
            &entry.path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        if meta.dev() != entry.dev || meta.ino() != entry.ino || !meta.is_file() {
            return Err(std::io::Error::other("file was replaced after it was copied"));
        }
        let want = usize::try_from(end - position).map_err(std::io::Error::other)?;
        let mut buf = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            match file.read_at(&mut buf[filled..], position + filled as u64) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits { max_total_bytes: 1 << 20, max_files: 100 }
    }

    #[test]
    fn builds_recursive_list_with_relative_paths() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(root.join("sub/deeper")).expect("mkdir");
        std::fs::write(root.join("a.txt"), b"hello").expect("write");
        std::fs::write(root.join("sub/b.bin"), vec![7u8; 1000]).expect("write");
        std::fs::write(root.join("sub/deeper/c.txt"), b"c").expect("write");
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).expect("symlink");
        let single = dir.path().join("single file.txt");
        std::fs::write(&single, b"xyz").expect("write");

        let list = LocalFileList::build(&[root.clone(), single], &limits()).expect("list");
        let names: Vec<(Option<&str>, &str, Option<u64>)> =
            list.descriptors().iter().map(|d| (d.relative_path.as_deref(), d.name.as_str(), d.file_size)).collect();
        assert_eq!(
            names,
            vec![
                (None, "proj", Some(0)),
                (Some("proj"), "a.txt", Some(5)),
                (Some("proj"), "sub", Some(0)),
                (Some("proj\\sub"), "b.bin", Some(1000)),
                (Some("proj\\sub"), "deeper", Some(0)),
                (Some("proj\\sub\\deeper"), "c.txt", Some(1)),
                (None, "single file.txt", Some(3)),
            ]
        );
        assert!(list.descriptors()[0].attributes.expect("attrs").contains(ClipboardFileAttributes::DIRECTORY));
        assert!(list.descriptors()[1].last_write_time.is_some());
        assert_eq!(list.read_range(3, 10, 20).expect("read"), vec![7u8; 20]);
        assert_eq!(list.read_range(1, 0, 100).expect("read"), b"hello");
        assert_eq!(list.read_range(1, 3, 100).expect("read"), b"lo");
        assert!(list.read_range(1, 5, 10).expect("read").is_empty());
        assert!(list.read_range(0, 0, 10).is_err(), "directories have no contents");
        assert!(list.read_range(99, 0, 10).is_err());
    }

    #[test]
    fn enforces_limits() {
        let dir = tempfile::tempdir().expect("tmp");
        let big = dir.path().join("big");
        std::fs::write(&big, vec![0u8; 2048]).expect("write");
        let small = Limits { max_total_bytes: 1024, max_files: 100 };
        assert!(matches!(LocalFileList::build(&[big], &small), Err(ListError::TooLarge { .. })));

        let many = dir.path().join("many");
        std::fs::create_dir(&many).expect("mkdir");
        for i in 0..5 {
            std::fs::write(many.join(format!("{i}")), b"x").expect("write");
        }
        let few = Limits { max_total_bytes: 1 << 20, max_files: 3 };
        assert!(matches!(LocalFileList::build(&[many], &few), Err(ListError::TooMany(_))));
        assert_eq!(
            LocalFileList::build(&[dir.path().join("missing")], &limits()).map(|l| l.len()),
            Err(ListError::Empty)
        );
    }

    #[test]
    fn refuses_swapped_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let f = dir.path().join("f");
        std::fs::write(&f, b"original").expect("write");
        let list = LocalFileList::build(std::slice::from_ref(&f), &limits()).expect("list");
        std::fs::remove_file(&f).expect("rm");
        std::os::unix::fs::symlink("/etc/hostname", &f).expect("symlink");
        assert!(list.read_range(0, 0, 8).is_err());
    }

    #[test]
    fn windows_names_are_made_safe() {
        assert_eq!(windows_safe_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(windows_safe_name("trailing."), "trailing_");
        assert_eq!(windows_safe_name(""), "_");
    }

    #[test]
    fn overlong_paths_are_skipped_not_shifted() {
        let dir = tempfile::tempdir().expect("tmp");
        let long = "x".repeat(200);
        let top = dir.path().join("t");
        std::fs::create_dir_all(top.join(&long)).expect("mkdir");
        std::fs::write(top.join(&long).join("y".repeat(100)), b"1").expect("write");
        std::fs::write(top.join("z"), b"2").expect("write");
        let list = LocalFileList::build(&[top], &limits()).expect("list");
        let names: Vec<&str> = list.descriptors().iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["t", long.as_str(), "z"]);
        assert_eq!(list.read_range(2, 0, 10).expect("read"), b"2");
    }
}
