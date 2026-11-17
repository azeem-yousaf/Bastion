//! Keyboard translation: Linux evdev keycodes → RDP (PS/2 set 1) scancodes,
//! keyboard-layout detection, and lock-key state.
//!
//! RDP transmits *physical* key positions; the remote Windows keyboard layout turns them
//! into characters. So we send scancodes and tell the server which layout to use.

use ironrdp_input::Scancode;

/// Maps an evdev keycode (as reported by winit's `to_scancode()` on Linux) to an RDP scancode.
pub fn evdev_to_scancode(code: u32) -> Option<Scancode> {
    let (ext, sc): (bool, u8) = match code {
        // evdev 1..=83 are identical to set-1 scancodes (Esc .. KP '.').
        1..=83 => (false, code as u8),
        85 => (false, 0x76),  // ZENKAKUHANKAKU
        86 => (false, 0x56),  // 102ND (ISO key left of Z: \| on UK)
        87 => (false, 0x57),  // F11
        88 => (false, 0x58),  // F12
        89 => (false, 0x73),  // RO
        90 => (false, 0x78),  // KATAKANA
        91 => (false, 0x77),  // HIRAGANA
        92 => (false, 0x79),  // HENKAN
        93 => (false, 0x70),  // KATAKANAHIRAGANA
        94 => (false, 0x7B),  // MUHENKAN
        95 => (false, 0x5C),  // KPJPCOMMA
        96 => (true, 0x1C),   // KPENTER
        97 => (true, 0x1D),   // RIGHTCTRL
        98 => (true, 0x35),   // KPSLASH
        99 => (true, 0x37),   // SYSRQ / PrintScreen
        100 => (true, 0x38),  // RIGHTALT (AltGr)
        102 => (true, 0x47),  // HOME
        103 => (true, 0x48),  // UP
        104 => (true, 0x49),  // PAGEUP
        105 => (true, 0x4B),  // LEFT
        106 => (true, 0x4D),  // RIGHT
        107 => (true, 0x4F),  // END
        108 => (true, 0x50),  // DOWN
        109 => (true, 0x51),  // PAGEDOWN
        110 => (true, 0x52),  // INSERT
        111 => (true, 0x53),  // DELETE
        113 => (true, 0x20),  // MUTE
        114 => (true, 0x2E),  // VOLUMEDOWN
        115 => (true, 0x30),  // VOLUMEUP
        116 => (true, 0x5E),  // POWER
        117 => (false, 0x59), // KPEQUAL
        121 => (false, 0x7E), // KPCOMMA
        122 => (false, 0x72), // HANGEUL
        123 => (false, 0x71), // HANJA
        124 => (false, 0x7D), // YEN
        125 => (true, 0x5B),  // LEFTMETA (Windows key)
        126 => (true, 0x5C),  // RIGHTMETA
        127 => (true, 0x5D),  // COMPOSE (Menu)
        140 => (true, 0x21),  // CALC
        142 => (true, 0x5F),  // SLEEP
        143 => (true, 0x63),  // WAKEUP
        155 => (true, 0x6C),  // MAIL
        156 => (true, 0x66),  // BOOKMARKS
        158 => (true, 0x6A),  // BACK
        159 => (true, 0x69),  // FORWARD
        163 => (true, 0x19),  // NEXTSONG
        164 => (true, 0x22),  // PLAYPAUSE
        165 => (true, 0x10),  // PREVIOUSSONG
        166 => (true, 0x24),  // STOPCD
        172 => (true, 0x32),  // HOMEPAGE
        173 => (true, 0x67),  // REFRESH
        183 => (false, 0x64), // F13
        184 => (false, 0x65),
        185 => (false, 0x66),
        186 => (false, 0x67),
        187 => (false, 0x68),
        188 => (false, 0x69),
        189 => (false, 0x6A),
        190 => (false, 0x6B),
        191 => (false, 0x6C),
        192 => (false, 0x6D),
        193 => (false, 0x6E),
        194 => (false, 0x76), // F24
        217 => (true, 0x65),  // SEARCH
        _ => return None,
    };
    Some(Scancode::from_u8(ext, sc))
}

/// evdev code of the Pause key, which RDP encodes specially (E1 prefix).
pub const EVDEV_PAUSE: u32 = 119;

/// Windows keyboard layout id (KLID) for an XKB layout/variant.
pub fn xkb_to_klid(layout: &str, variant: &str) -> u32 {
    match (layout, variant) {
        ("us", "intl" | "altgr-intl") => 0x0002_0409,
        ("us", "dvorak") => 0x0001_0409,
        ("us", "colemak") => 0x0409,
        ("gb", "extd") => 0x0001_0809,
        ("de", "neo") => 0x0407,
        ("ch", "fr") => 0x100C,
        ("ca", "fr" | "multix") => 0x1009,
        ("be", _) => 0x080C,
        ("ch", _) => 0x0807,
        ("ca", _) => 0x1009,
        ("us", _) => 0x0409,
        ("gb", _) => 0x0809,
        ("ie", _) => 0x1809,
        ("de", _) => 0x0407,
        ("at", _) => 0x0C07,
        ("fr", _) => 0x040C,
        ("es", _) => 0x040A,
        ("latam", _) => 0x080A,
        ("it", _) => 0x0410,
        ("pt", _) => 0x0816,
        ("br", _) => 0x0416,
        ("nl", _) => 0x0413,
        ("se", _) => 0x041D,
        ("no", _) => 0x0414,
        ("dk", _) => 0x0406,
        ("fi", _) => 0x040B,
        ("is", _) => 0x040F,
        ("pl", _) => 0x0415,
        ("cz", _) => 0x0405,
        ("sk", _) => 0x041B,
        ("hu", _) => 0x040E,
        ("ro", _) => 0x0418,
        ("hr" | "si", _) => 0x041A,
        ("gr", _) => 0x0408,
        ("tr", _) => 0x041F,
        ("ru", _) => 0x0419,
        ("ua", _) => 0x0422,
        ("il", _) => 0x040D,
        ("ara", _) => 0x0401,
        ("jp", _) => 0x0411,
        ("kr", _) => 0x0412,
        ("cn", _) => 0x0804,
        ("tw", _) => 0x0404,
        ("in", _) => 0x4009,
        _ => 0x0409,
    }
}

fn first_csv(s: &str) -> String {
    s.split(',').next().unwrap_or("").trim().to_owned()
}

/// Detects the active XKB layout: KDE (`kxkbrc`) → env → system (`00-keyboard.conf`).
pub fn detect_layout() -> (String, String) {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    if let Some(home) = &home
        && let Ok(text) = std::fs::read_to_string(home.join(".config/kxkbrc"))
    {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .map(first_csv)
                .filter(|v| !v.is_empty())
        };
        if let Some(layout) = get("LayoutList") {
            return (layout, get("VariantList").unwrap_or_default());
        }
    }
    if let Ok(layout) = std::env::var("XKB_DEFAULT_LAYOUT") {
        return (first_csv(&layout), std::env::var("XKB_DEFAULT_VARIANT").map(|v| first_csv(&v)).unwrap_or_default());
    }
    if let Ok(text) = std::fs::read_to_string("/etc/X11/xorg.conf.d/00-keyboard.conf") {
        let get = |k: &str| {
            text.lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix("Option")
                    .map(str::trim)
                    .and_then(|r| r.strip_prefix(&format!("\"{k}\"")))
                    .map(|v| first_csv(v.trim().trim_matches('"')))
            })
        };
        if let Some(layout) = get("XkbLayout") {
            return (layout, get("XkbVariant").unwrap_or_default());
        }
    }
    ("us".to_owned(), String::new())
}

pub fn detect_klid() -> u32 {
    let (layout, variant) = detect_layout();
    let klid = xkb_to_klid(&layout, &variant);
    tracing::info!(%layout, %variant, klid = format_args!("{klid:#010x}"), "Detected keyboard layout");
    klid
}

/// Lock-key LEDs read from sysfs (no special permissions needed).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LockState {
    pub caps: bool,
    pub num: bool,
    pub scroll: bool,
}

pub fn read_lock_state() -> LockState {
    let mut s = LockState::default();
    let Ok(dir) = std::fs::read_dir("/sys/class/leds") else { return s };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let on = || std::fs::read_to_string(entry.path().join("brightness")).map(|v| v.trim() != "0").unwrap_or(false);
        if name.ends_with("::capslock") {
            s.caps |= on();
        } else if name.ends_with("::numlock") {
            s.num |= on();
        } else if name.ends_with("::scrolllock") {
            s.scroll |= on();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_and_extended() {
        assert_eq!(evdev_to_scancode(30).unwrap().as_u8(), (false, 0x1E)); // A
        assert_eq!(evdev_to_scancode(103).unwrap().as_u8(), (true, 0x48)); // Up
        assert_eq!(evdev_to_scancode(100).unwrap().as_u8(), (true, 0x38)); // AltGr
        assert_eq!(evdev_to_scancode(86).unwrap().as_u8(), (false, 0x56)); // UK backslash
        assert!(evdev_to_scancode(0).is_none());
    }

    #[test]
    fn layouts() {
        assert_eq!(xkb_to_klid("gb", ""), 0x0809);
        assert_eq!(xkb_to_klid("us", "intl"), 0x0002_0409);
        assert_eq!(xkb_to_klid("zz", ""), 0x0409);
    }
}
