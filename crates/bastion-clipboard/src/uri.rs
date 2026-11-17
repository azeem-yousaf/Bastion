//! `text/uri-list` (RFC 2483) and `x-special/gnome-copied-files` parsing and generation for
//! local `file://` URIs.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, percent_encode};

/// Everything except RFC 3986 unreserved characters and `/` gets percent-encoded.
const PATH_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'/').remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Parses one URI into a local absolute path. Returns `None` for non-`file` URIs, URIs naming a
/// remote host, relative paths and paths containing NUL.
pub(crate) fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let uri = uri.trim();
    let rest = uri.get(..5).filter(|s| s.eq_ignore_ascii_case("file:")).and_then(|_| uri.get(5..))?;
    let path = if let Some(after) = rest.strip_prefix("//") {
        // authority: empty or localhost only.
        let slash = after.find('/')?;
        let host = &after[..slash];
        if !(host.is_empty() || host.eq_ignore_ascii_case("localhost")) {
            return None;
        }
        &after[slash..]
    } else {
        rest
    };
    if !path.starts_with('/') {
        return None;
    }
    // Drop query/fragment (not meaningful for file URIs, but some apps append them).
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let bytes: Vec<u8> = percent_decode_str(path).collect();
    if bytes.contains(&0) {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(bytes)))
}

/// Parses `text/uri-list` content into local paths, skipping comments and non-file URIs.
pub(crate) fn parse_uri_list(data: &[u8]) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(data);
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(file_uri_to_path).collect()
}

/// Parses `x-special/gnome-copied-files` (`copy\nURI\nURI...` or `cut\n...`).
pub(crate) fn parse_gnome_copied_files(data: &[u8]) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    match lines.next().map(str::trim) {
        Some("copy" | "cut") => {}
        _ => return Vec::new(),
    }
    lines.map(str::trim).filter(|l| !l.is_empty()).filter_map(file_uri_to_path).collect()
}

/// `file:///...` URI for an absolute local path.
pub(crate) fn path_to_file_uri(path: &Path) -> String {
    format!("file://{}", percent_encode(path.as_os_str().as_bytes(), PATH_SET))
}

/// Builds `text/uri-list` content (CRLF separated, as RFC 2483 requires).
pub(crate) fn build_uri_list(paths: &[PathBuf]) -> Vec<u8> {
    let mut out = String::new();
    for p in paths {
        out.push_str(&path_to_file_uri(p));
        out.push_str("\r\n");
    }
    out.into_bytes()
}

/// Builds `x-special/gnome-copied-files` content.
pub(crate) fn build_gnome_copied_files(paths: &[PathBuf]) -> Vec<u8> {
    let mut out = String::from("copy");
    for p in paths {
        out.push('\n');
        out.push_str(&path_to_file_uri(p));
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and_localhost() {
        assert_eq!(file_uri_to_path("file:///home/u/a.txt"), Some(PathBuf::from("/home/u/a.txt")));
        assert_eq!(file_uri_to_path("FILE://localhost/tmp/x"), Some(PathBuf::from("/tmp/x")));
        assert_eq!(file_uri_to_path("file:/tmp/y"), Some(PathBuf::from("/tmp/y")));
    }

    #[test]
    fn rejects_remote_and_other_schemes() {
        assert_eq!(file_uri_to_path("file://otherhost/etc/passwd"), None);
        assert_eq!(file_uri_to_path("https://example.com/a"), None);
        assert_eq!(file_uri_to_path("file:relative/path"), None);
        assert_eq!(file_uri_to_path("file:///a%00b"), None);
        assert_eq!(file_uri_to_path("fil"), None);
    }

    #[test]
    fn percent_decoding_spaces_and_unicode() {
        assert_eq!(
            file_uri_to_path("file:///home/u/My%20Docs/r%C3%A9sum%C3%A9%20%E2%9C%93.pdf"),
            Some(PathBuf::from("/home/u/My Docs/r\u{e9}sum\u{e9} \u{2713}.pdf"))
        );
        // Non-UTF-8 bytes survive as raw OS bytes.
        let p = file_uri_to_path("file:///tmp/%FF").expect("path");
        assert_eq!(p.as_os_str().as_bytes(), b"/tmp/\xff");
    }

    #[test]
    fn uri_list_with_comments_and_crlf() {
        let data = b"# comment\r\nfile:///a/b%20c\r\nhttps://x.y/z\r\n\r\nfile:///d\n";
        assert_eq!(parse_uri_list(data), vec![PathBuf::from("/a/b c"), PathBuf::from("/d")]);
    }

    #[test]
    fn gnome_copied_files() {
        let data = b"copy\nfile:///a\nfile:///b%23c";
        assert_eq!(parse_gnome_copied_files(data), vec![PathBuf::from("/a"), PathBuf::from("/b#c")]);
        assert!(parse_gnome_copied_files(b"file:///a").is_empty());
    }

    #[test]
    fn build_round_trip() {
        let paths =
            vec![PathBuf::from("/tmp/with space/#hash?.txt"), PathBuf::from("/tmp/\u{65e5}\u{672c}/\u{1F600}%.txt")];
        let list = build_uri_list(&paths);
        assert!(String::from_utf8(list.clone()).expect("ascii").is_ascii());
        assert_eq!(parse_uri_list(&list), paths);
        assert_eq!(parse_gnome_copied_files(&build_gnome_copied_files(&paths)), paths);
        assert_eq!(path_to_file_uri(Path::new("/a b")), "file:///a%20b");
    }
}
