//! KDE Plasma (KWin) integration.
//!
//! Wayland does not let an application un-minimise its own windows. In a multi-monitor session
//! each monitor has its own window, and restoring one from the taskbar leaves the others
//! minimised. On KWin we ask the compositor (via its scripting D-Bus API) to restore and raise
//! the session's other windows — matched by our process id *and* exact window title, so no other
//! application's windows are ever touched.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

/// Escapes a string as a JavaScript string literal (JSON is valid JS).
fn js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The KWin script that restores and raises our windows with `caption`.
pub fn restore_script(pid: u32, caption: &str) -> String {
    format!(
        "const PID = {pid};\nconst CAPTION = {};\n\
         for (const w of workspace.windowList()) {{\n\
         \x20   if (w.pid === PID && w.caption === CAPTION) {{\n\
         \x20       w.minimized = false;\n\
         \x20       if (typeof workspace.raiseWindow === \"function\") {{ workspace.raiseWindow(w); }}\n\
         \x20   }}\n\
         }}\n",
        js_string(caption)
    )
}

/// The private per-user directory the script is written to: `$XDG_RUNTIME_DIR`, and only if it
/// is absolute, owned by us and closed to everyone else. There is deliberately no fallback to a
/// shared temp directory — KWin executes whatever the path holds, so the restore is skipped.
fn private_runtime_dir(var: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let dir = PathBuf::from(var?);
    if !dir.is_absolute() {
        return None;
    }
    let meta = std::fs::metadata(&dir).ok()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    (meta.is_dir() && meta.uid() == me && meta.mode() & 0o077 == 0).then_some(dir)
}

/// A script file that is deleted when dropped (on every path, including errors).
struct ScriptFile(PathBuf);

impl ScriptFile {
    /// Creates `path` exclusively (it must not exist, not even as a symlink), readable and
    /// writable by the owner only.
    fn create_at(path: PathBuf, source: &str) -> std::io::Result<Self> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        // From here on the file is ours: remove it whatever happens.
        let file = Self(path);
        f.write_all(source.as_bytes())?;
        f.sync_data().ok();
        Ok(file)
    }

    /// Writes `source` under an unpredictable name in `dir`.
    fn create_in(dir: &Path, source: &str) -> std::io::Result<Self> {
        let name = format!("bastion-kwin-{}.js", uuid::Uuid::new_v4().simple());
        Self::create_at(dir.join(name), source)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScriptFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run_script(source: &str) -> zbus::Result<()> {
    let Some(dir) = private_runtime_dir(std::env::var_os("XDG_RUNTIME_DIR")) else {
        tracing::debug!("No private runtime directory; KWin window restore skipped");
        return Ok(());
    };
    let conn = zbus::blocking::Connection::session()?;
    let file = ScriptFile::create_in(&dir, source)?;
    let name = format!("bastion-restore-{}", std::process::id());
    let scripting = zbus::blocking::Proxy::new(&conn, "org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting")?;
    let _: bool = scripting.call("unloadScript", &(name.as_str(),)).unwrap_or(false);
    let id: i32 = scripting.call("loadScript", &(file.path().to_string_lossy().as_ref(), name.as_str()))?;
    let script =
        zbus::blocking::Proxy::new(&conn, "org.kde.KWin", format!("/Scripting/Script{id}"), "org.kde.kwin.Script")?;
    let run: zbus::Result<()> = script.call("run", &());
    let _: bool = scripting.call("unloadScript", &(name.as_str(),)).unwrap_or(false);
    drop(file);
    run
}

/// Restores (un-minimises and raises) every window of this process titled `caption`.
/// Runs in the background; silently does nothing outside KWin.
pub fn restore_windows(caption: String) {
    let source = restore_script(std::process::id(), &caption);
    std::thread::spawn(move || {
        if let Err(e) = run_script(&source) {
            tracing::debug!(error = %e, "KWin window restore unavailable");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caption_is_safely_escaped() {
        let s = restore_script(42, "Work \"PC\" \\ </script>\n — Bastion");
        assert!(s.contains("const PID = 42;"));
        assert!(s.contains(r#"const CAPTION = "Work \"PC\" \\ </script>\u000a — Bastion";"#), "{s}");
        // The only executable statements are the fixed template.
        assert_eq!(s.matches("w.minimized = false").count(), 1);
    }

    /// Decodes the literal `js_string` produced, the way a JavaScript engine would.
    fn js_decode(lit: &str) -> String {
        let inner = lit.strip_prefix('"').and_then(|l| l.strip_suffix('"')).expect("quoted");
        let mut out = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            assert_ne!(c, '"', "unescaped quote ends the literal early: {lit}");
            assert!(c as u32 >= 0x20 && c != '\u{2028}' && c != '\u{2029}', "raw line terminator/control in {lit}");
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next().expect("escape") {
                'u' => {
                    let hex: String = it.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
                }
                c @ ('"' | '\\') => out.push(c),
                other => panic!("unexpected escape \\{other}"),
            }
        }
        out
    }

    #[test]
    fn hostile_titles_stay_inside_the_string_literal() {
        // Profile names come from .rdp files and the user; none may break out of the literal.
        for title in [
            "\";callDBus(\"org.freedesktop.systemd1\");//",
            "a\\",
            "a\\\"; evil(); \"",
            "line\nbreak\rcr\u{2028}ls\u{2029}ps\0nul\u{1b}esc",
            "*/ </script> ${x} `tick` 'single'",
            "emoji \u{1F600} — Bastion",
            "",
        ] {
            let lit = js_string(title);
            assert_eq!(js_decode(&lit), title, "{lit}");
            let script = restore_script(u32::MAX, title);
            assert!(script.starts_with("const PID = 4294967295;\nconst CAPTION = "));
            assert_eq!(script.lines().count(), 8, "a title must not add lines: {script}");
        }
    }

    #[test]
    fn script_directory_must_be_private_and_absolute() {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(private_runtime_dir(None), None, "no runtime dir: skip, never fall back to /tmp");
        assert_eq!(private_runtime_dir(Some("".into())), None);
        assert_eq!(private_runtime_dir(Some("relative/dir".into())), None);
        assert_eq!(private_runtime_dir(Some("/nonexistent/bastion-test".into())), None);
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(private_runtime_dir(Some(dir.path().into())), Some(dir.path().to_owned()));
        // Readable or writable by others (like /tmp): refused.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(private_runtime_dir(Some(dir.path().into())), None);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(private_runtime_dir(Some(dir.path().into())), None);
        // A file is not a directory.
        let file = dir.path().join("f");
        std::fs::write(&file, "").unwrap();
        assert_eq!(private_runtime_dir(Some(file.into())), None);
    }

    #[test]
    fn script_file_is_private_unpredictable_and_removed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let a = ScriptFile::create_in(dir.path(), "const A = 1;\n").unwrap();
        let b = ScriptFile::create_in(dir.path(), "const B = 2;\n").unwrap();
        assert_ne!(a.path(), b.path());
        let name = a.path().file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), "bastion-kwin-.js".len() + 32, "{name}");
        assert_eq!(std::fs::metadata(a.path()).unwrap().permissions().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read_to_string(a.path()).unwrap(), "const A = 1;\n");
        let (pa, pb) = (a.path().to_owned(), b.path().to_owned());
        drop(a);
        drop(b);
        assert!(!pa.exists() && !pb.exists(), "scripts are removed after use");
    }

    #[test]
    fn script_file_never_reuses_an_existing_path_or_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-created by someone else: must fail, and must not be written to or deleted.
        let planted = dir.path().join("planted.js");
        std::fs::write(&planted, "attacker").unwrap();
        assert!(ScriptFile::create_at(planted.clone(), "ours").is_err());
        assert_eq!(std::fs::read_to_string(&planted).unwrap(), "attacker");
        // A symlink to a victim file: not followed, target untouched.
        let target = dir.path().join("victim.txt");
        std::fs::write(&target, "precious").unwrap();
        let link = dir.path().join("link.js");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(ScriptFile::create_at(link.clone(), "ours").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
        // A dangling symlink must not be created through either.
        let dangling = dir.path().join("dangling.js");
        std::os::unix::fs::symlink(dir.path().join("new-file"), &dangling).unwrap();
        assert!(ScriptFile::create_at(dangling, "ours").is_err());
        assert!(!dir.path().join("new-file").exists());
    }
}
