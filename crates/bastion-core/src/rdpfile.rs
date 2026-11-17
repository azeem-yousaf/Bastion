//! Import Microsoft `.rdp` files into a [`Profile`].
//!
//! `.rdp` files are usually UTF-16LE with a BOM (as written by mstsc), sometimes UTF-8.
//! Passwords embedded in `.rdp` files (`password 51:b:` DPAPI blobs) cannot be decrypted
//! off-Windows and are intentionally ignored.

use anyhow::{Result, bail};
use ironrdp_propertyset::PropertySet;

use crate::profile::{DEFAULT_GATEWAY_PORT, DEFAULT_RDP_PORT, DisplayMode, GatewaySettings, Profile};

const MAX_RDP_FILE_BYTES: usize = 1024 * 1024;

/// Decodes raw file bytes (UTF-16LE/BE with BOM, or UTF-8 with/without BOM).
pub fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_RDP_FILE_BYTES {
        bail!("file is too large to be an .rdp file");
    }
    let (enc, bom_len) = encoding_rs::Encoding::for_bom(bytes).unwrap_or_else(|| {
        // No BOM: guess UTF-16LE if every other byte is NUL in the first chunk.
        let looks_utf16 = bytes.len() >= 4 && bytes.iter().skip(1).step_by(2).take(32).all(|&b| b == 0);
        if looks_utf16 { (encoding_rs::UTF_16LE, 0) } else { (encoding_rs::UTF_8, 0) }
    });
    let (text, _, had_errors) = enc.decode(&bytes[bom_len..]);
    if had_errors && enc == encoding_rs::UTF_8 {
        bail!("file is not valid UTF-8 or UTF-16 text");
    }
    Ok(text.into_owned())
}

/// Splits "host[:port]" honouring IPv6 brackets.
fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default_port);
        return (host.to_owned(), port);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => match p.parse() {
            Ok(port) => (h.to_owned(), port),
            Err(_) => (s.to_owned(), default_port),
        },
        _ => (s.to_owned(), default_port),
    }
}

fn split_user(raw: &str) -> (String, String) {
    match raw.split_once('\\') {
        Some((d, u)) => (d.to_owned(), u.to_owned()),
        None => (String::new(), raw.to_owned()),
    }
}

/// Parses `.rdp` text into a new profile. Unknown keys are ignored; warnings are returned.
pub fn import(text: &str, fallback_name: &str) -> (Profile, Vec<String>) {
    // Normalise: strip CR, drop blank lines (the parser treats them as malformed).
    let cleaned: String = text
        .lines()
        .map(|l| l.trim_end_matches('\r').trim_start_matches('\u{feff}'))
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = ironrdp_rdpfile::parse(&cleaned);
    let props: PropertySet = parsed.properties;
    let mut warnings: Vec<String> = Vec::new();
    let skipped = parsed.errors.len();
    if skipped > 0 {
        warnings.push(format!("{skipped} line(s) were not understood and were skipped."));
    }

    let s = |k: &str| props.get::<&str>(k).map(str::to_owned);
    let i = |k: &str| props.get::<i64>(k);

    let mut p = Profile::default();

    if let Some(addr) = s("full address").or_else(|| s("alternate full address")) {
        let (host, port) = split_host_port(&addr, DEFAULT_RDP_PORT);
        p.host = host;
        p.port = i("server port").and_then(|v| u16::try_from(v).ok()).unwrap_or(port);
    }
    if let Some(user) = s("username") {
        let (d, u) = split_user(&user);
        p.domain = s("domain").unwrap_or(d);
        p.username = u;
    }

    // Gateway: usage method 0 = direct, 1 = always, 2 = detect, 3 = default, 4 = none.
    let gw_host = s("gatewayhostname").filter(|h| !h.trim().is_empty());
    let usage = i("gatewayusagemethod").unwrap_or(if gw_host.is_some() { 1 } else { 0 });
    if let (Some(h), true) = (gw_host, matches!(usage, 1..=3)) {
        let (host, port) = split_host_port(&h, DEFAULT_GATEWAY_PORT);
        let mut gw = GatewaySettings { host, port, ..Default::default() };
        // promptcredentialonce:i:1 = reuse credentials for gateway and host (mstsc default).
        gw.same_credentials = i("promptcredentialonce").unwrap_or(1) == 1;
        if usage == 2 {
            warnings.push("Gateway was set to auto-detect; Bastion will always use it.".to_owned());
        }
        match i("gatewaycredentialssource") {
            None | Some(0) | Some(4) => {}
            Some(other) => warnings.push(format!(
                "Gateway credential source {other} (smart card / cookie) is not supported yet; using password."
            )),
        }
        p.gateway = Some(gw);
    }

    // Display.
    if i("screen mode id") == Some(2) {
        p.display.mode = if i("use multimon") == Some(1) { DisplayMode::AllMonitors } else { DisplayMode::Fullscreen };
    }
    if let (Some(w), Some(h)) = (i("desktopwidth"), i("desktopheight"))
        && let (Ok(w), Ok(h)) = (u16::try_from(w), u16::try_from(h))
        && w >= 200
        && h >= 200
    {
        p.display.width = w;
        p.display.height = h;
    }
    if let Some(v) = i("dynamic resolution") {
        p.display.dynamic_resolution = v == 1;
    }

    // Audio: audiomode 0 = play here, 1 = play on remote, 2 = none.
    if let Some(m) = i("audiomode") {
        p.audio.playback = m == 0;
    }
    if let Some(m) = i("audiocapturemode") {
        p.audio.microphone = m == 1;
    }

    // Cameras: `*` = all, otherwise a ';'-separated list of device ids (Windows-specific).
    if let Some(c) = s("camerastoredirect").as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        p.camera.enabled = true;
        if c != "*" {
            warnings.push("The file lists specific cameras; Bastion shares all of this computer's webcams.".to_owned());
        }
    }

    // Clipboard.
    if let Some(v) = i("redirectclipboard") {
        p.clipboard.enabled = v == 1;
    }

    // Drives: never auto-enable sharing from an imported file (user policy: off by default).
    if s("drivestoredirect").is_some_and(|d| !d.trim().is_empty()) || i("redirectdrives") == Some(1) {
        warnings.push(
            "The file requests drive redirection; it was left OFF. Enable it per connection if wanted.".to_owned(),
        );
    }

    if props.get::<&str>("password 51").is_some() {
        warnings.push("Saved Windows password in the file was ignored (cannot be decrypted on Linux).".to_owned());
    }
    if i("authentication level") == Some(0) {
        warnings.push("The file disables server authentication; Bastion still verifies certificates.".to_owned());
    }

    p.name = fallback_name.to_owned();
    if p.host.is_empty() {
        warnings.push("No 'full address' found in the file.".to_owned());
    }
    (p, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "screen mode id:i:2\r\nuse multimon:i:1\r\ndesktopwidth:i:1920\r\ndesktopheight:i:1080\r\n\
full address:s:pc01.corp.local:3390\r\nusername:s:CORP\\alice\r\ngatewayhostname:s:rdg.corp.com\r\n\
gatewayusagemethod:i:1\r\ngatewaycredentialssource:i:0\r\npromptcredentialonce:i:1\r\naudiomode:i:0\r\n\
audiocapturemode:i:1\r\nredirectclipboard:i:1\r\ndrivestoredirect:s:*\r\n\r\n";

    #[test]
    fn imports_typical_file() {
        let (p, warnings) = import(SAMPLE, "Work PC");
        assert_eq!(p.host, "pc01.corp.local");
        assert_eq!(p.port, 3390);
        assert_eq!(p.domain, "CORP");
        assert_eq!(p.username, "alice");
        let gw = p.gateway.unwrap();
        assert_eq!(gw.host, "rdg.corp.com");
        assert_eq!(gw.port, 443);
        assert!(gw.same_credentials);
        assert_eq!(p.display.mode, DisplayMode::AllMonitors);
        assert!(p.audio.playback && p.audio.microphone && p.clipboard.enabled);
        assert!(!p.drive.enabled);
        assert!(warnings.iter().any(|w| w.contains("drive")));
    }

    #[test]
    fn camera_redirection_is_imported() {
        assert!(!import(SAMPLE, "x").0.camera.enabled);
        let (p, w) = import("full address:s:pc01\r\ncamerastoredirect:s:*\r\n", "x");
        assert!(p.camera.enabled && w.is_empty(), "{w:?}");
        let (p, w) = import("full address:s:pc01\r\ncamerastoredirect:s:\\\\?\\usb#vid_046d\r\n", "x");
        assert!(p.camera.enabled);
        assert!(w.iter().any(|w| w.contains("all of this computer's webcams")), "{w:?}");
    }

    #[test]
    fn decodes_utf16_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in "full address:s:host1\r\n".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let text = decode_text(&bytes).unwrap();
        let (p, _) = import(&text, "x");
        assert_eq!(p.host, "host1");
    }

    #[test]
    fn host_port_split() {
        assert_eq!(split_host_port("[fe80::1]:5000", 1), ("fe80::1".into(), 5000));
        assert_eq!(split_host_port("fe80::1", 1), ("fe80::1".into(), 1));
        assert_eq!(split_host_port("h:x", 7), ("h:x".into(), 7));
    }
}
