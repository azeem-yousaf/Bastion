//! KDE Plasma (KWin) integration.
//!
//! Wayland does not let an application un-minimise its own windows. In a multi-monitor session
//! each monitor has its own window, and restoring one from the taskbar leaves the others
//! minimised. On KWin we ask the compositor (via its scripting D-Bus API) to restore and raise
//! the session's other windows — matched by our process id *and* exact window title, so no other
//! application's windows are ever touched.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

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

fn run_script(source: &str) -> zbus::Result<()> {
    let conn = zbus::blocking::Connection::session()?;
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("bastion-kwin-{}.js", std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
        f.write_all(source.as_bytes())?;
    }
    let name = format!("bastion-restore-{}", std::process::id());
    let scripting = zbus::blocking::Proxy::new(&conn, "org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting")?;
    let _: bool = scripting.call("unloadScript", &(name.as_str(),)).unwrap_or(false);
    let id: i32 = scripting.call("loadScript", &(path.to_string_lossy().as_ref(), name.as_str()))?;
    let script =
        zbus::blocking::Proxy::new(&conn, "org.kde.KWin", format!("/Scripting/Script{id}"), "org.kde.kwin.Script")?;
    let run: zbus::Result<()> = script.call("run", &());
    let _: bool = scripting.call("unloadScript", &(name.as_str(),)).unwrap_or(false);
    let _ = std::fs::remove_file(&path);
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
}
