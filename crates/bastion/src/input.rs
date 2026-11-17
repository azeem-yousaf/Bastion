//! Local input → RDP input events. Pure logic (no windowing types) so it is unit-testable.

use bastion_session::keyboard::{EVDEV_PAUSE, LockState, evdev_to_scancode};
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use smallvec::SmallVec;

pub type Events = SmallVec<[FastPathInputEvent; 2]>;

/// evdev codes used by the release chord (Ctrl+Alt+Home).
const EV_LCTRL: u32 = 29;
const EV_RCTRL: u32 = 97;
const EV_LALT: u32 = 56;
const EV_RALT: u32 = 100;
const EV_HOME: u32 = 102;

/// Maps a point in window pixels to remote-desktop pixels.
///
/// `view` is where the remote image is drawn inside the window (x, y, w, h in window pixels);
/// `src` is which part of the remote desktop that view shows (x, y, w, h in remote pixels).
pub fn map_point(px: f64, py: f64, view: (f64, f64, f64, f64), src: (f64, f64, f64, f64)) -> Option<(u16, u16)> {
    let (vx, vy, vw, vh) = view;
    if vw <= 0.0 || vh <= 0.0 {
        return None;
    }
    let rx = src.0 + (px - vx) * src.2 / vw;
    let ry = src.1 + (py - vy) * src.3 / vh;
    let clamp = |v: f64, lo: f64, hi: f64| v.max(lo).min(hi - 1.0).max(0.0);
    let x = clamp(rx, src.0, src.0 + src.2);
    let y = clamp(ry, src.1, src.1 + src.3);
    Some((x.round() as u16, y.round() as u16))
}

/// Stateful translator for one session.
pub struct InputState {
    db: Database,
    wheel_accum_v: f64,
    wheel_accum_h: f64,
    held_evdev: Vec<u32>,
}

/// What the UI should do in response to a key.
#[derive(Debug, PartialEq)]
pub enum KeyOutcome {
    Send(Events),
    /// The release chord was pressed: toggle grab / show the session bar.
    ReleaseChord(Events),
    Ignore,
}

impl Default for InputState {
    fn default() -> Self {
        Self::new()
    }
}

impl InputState {
    pub fn new() -> Self {
        Self { db: Database::new(), wheel_accum_v: 0.0, wheel_accum_h: 0.0, held_evdev: Vec::new() }
    }

    pub fn key(&mut self, evdev: u32, pressed: bool, repeat: bool) -> KeyOutcome {
        if pressed {
            if !self.held_evdev.contains(&evdev) {
                self.held_evdev.push(evdev);
            }
        } else {
            self.held_evdev.retain(|&k| k != evdev);
        }

        if pressed && evdev == EV_HOME && self.chord_modifiers_held() {
            // Release everything remotely so no modifier stays stuck on the server.
            return KeyOutcome::ReleaseChord(self.release_all());
        }

        if evdev == EVDEV_PAUSE {
            // Pause is "E1 1D 45": Ctrl with the extended-1 prefix followed by NumLock.
            if !pressed {
                return KeyOutcome::Ignore;
            }
            let mut ev = Events::new();
            ev.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED1, 0x1D));
            ev.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x45));
            ev.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED1 | KeyboardFlags::RELEASE, 0x1D));
            ev.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, 0x45));
            return KeyOutcome::Send(ev);
        }

        let Some(sc) = evdev_to_scancode(evdev) else {
            tracing::debug!(evdev, "Unmapped key");
            return KeyOutcome::Ignore;
        };
        if pressed && repeat && self.db.is_key_pressed(sc) {
            // Typematic repeat: the database suppresses duplicate presses, so emit directly.
            return KeyOutcome::Send(smallvec::smallvec![key_event(sc, true)]);
        }
        let op = if pressed { Operation::KeyPressed(sc) } else { Operation::KeyReleased(sc) };
        let ev = self.db.apply([op]);
        if ev.is_empty() { KeyOutcome::Ignore } else { KeyOutcome::Send(ev) }
    }

    fn chord_modifiers_held(&self) -> bool {
        let ctrl = self.held_evdev.iter().any(|&k| k == EV_LCTRL || k == EV_RCTRL);
        let alt = self.held_evdev.iter().any(|&k| k == EV_LALT || k == EV_RALT);
        ctrl && alt
    }

    pub fn mouse_move(&mut self, x: u16, y: u16) -> Events {
        self.db.apply([Operation::MouseMove(MousePosition { x, y })])
    }

    pub fn mouse_button(&mut self, button: MouseButton, pressed: bool) -> Events {
        self.db.apply([if pressed {
            Operation::MouseButtonPressed(button)
        } else {
            Operation::MouseButtonReleased(button)
        }])
    }

    /// `dy`/`dx` in "lines" (1.0 = one wheel notch). Positive dy = scroll up / away from user.
    pub fn wheel_lines(&mut self, dx: f64, dy: f64) -> Events {
        self.wheel_accum_v += dy * 120.0;
        self.wheel_accum_h += dx * 120.0;
        self.flush_wheel()
    }

    /// Smooth (touchpad) scrolling in pixels.
    pub fn wheel_pixels(&mut self, dx: f64, dy: f64) -> Events {
        // ~ 40 px per notch feels like native Windows touchpad scrolling.
        self.wheel_accum_v += dy * 3.0;
        self.wheel_accum_h += dx * 3.0;
        self.flush_wheel()
    }

    fn flush_wheel(&mut self) -> Events {
        let mut ops = Vec::new();
        for (acc, vertical) in [(&mut self.wheel_accum_v, true), (&mut self.wheel_accum_h, false)] {
            let units = acc.trunc().clamp(-255.0, 255.0);
            if units.abs() >= 1.0 {
                *acc -= units;
                // RDP horizontal wheel is positive to the left.
                let units = if vertical { units } else { -units };
                ops.push(Operation::WheelRotations(WheelRotations {
                    is_vertical: vertical,
                    rotation_units: units as i16,
                }));
            }
        }
        self.db.apply(ops)
    }

    /// Releases every key/button the server believes is down (on focus loss, chord, disconnect).
    pub fn release_all(&mut self) -> Events {
        self.held_evdev.clear();
        self.db.release_all()
    }

    /// Lock-key synchronisation (sent on focus gain).
    pub fn sync_locks(&self, l: LockState) -> Events {
        smallvec::smallvec![ironrdp_input::synchronize_event(l.scroll, l.num, l.caps, false)]
    }
}

fn key_event(sc: Scancode, pressed: bool) -> FastPathInputEvent {
    let (ext, code) = sc.as_u8();
    let mut flags = if pressed { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
    if ext {
        flags |= KeyboardFlags::EXTENDED;
    }
    FastPathInputEvent::KeyboardEvent(flags, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(o: &KeyOutcome) -> Vec<(KeyboardFlags, u8)> {
        let ev = match o {
            KeyOutcome::Send(e) | KeyOutcome::ReleaseChord(e) => e,
            KeyOutcome::Ignore => return vec![],
        };
        ev.iter()
            .filter_map(|e| match e {
                FastPathInputEvent::KeyboardEvent(f, c) => Some((*f, *c)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn press_release_and_repeat() {
        let mut s = InputState::new();
        assert_eq!(keys(&s.key(30, true, false)), vec![(KeyboardFlags::empty(), 0x1E)]);
        assert_eq!(keys(&s.key(30, true, true)), vec![(KeyboardFlags::empty(), 0x1E)], "repeat must be sent");
        assert_eq!(keys(&s.key(30, false, false)), vec![(KeyboardFlags::RELEASE, 0x1E)]);
        assert_eq!(s.key(30, false, false), KeyOutcome::Ignore, "double release suppressed");
    }

    #[test]
    fn extended_keys_carry_flag() {
        let mut s = InputState::new();
        assert_eq!(keys(&s.key(103, true, false)), vec![(KeyboardFlags::EXTENDED, 0x48)]);
    }

    #[test]
    fn release_chord_releases_modifiers_remotely() {
        let mut s = InputState::new();
        s.key(EV_LCTRL, true, false);
        s.key(EV_LALT, true, false);
        let out = s.key(EV_HOME, true, false);
        assert!(matches!(out, KeyOutcome::ReleaseChord(_)));
        let released = keys(&out);
        assert!(released.contains(&(KeyboardFlags::RELEASE, 0x1D)));
        assert!(released.contains(&(KeyboardFlags::RELEASE, 0x38)));
    }

    #[test]
    fn pause_uses_e1_sequence() {
        let mut s = InputState::new();
        let k = keys(&s.key(EVDEV_PAUSE, true, false));
        assert_eq!(k[0], (KeyboardFlags::EXTENDED1, 0x1D));
        assert_eq!(k.len(), 4);
        assert_eq!(s.key(EVDEV_PAUSE, false, false), KeyOutcome::Ignore);
    }

    #[test]
    fn wheel_accumulates_smooth_scroll() {
        let mut s = InputState::new();
        assert!(s.wheel_pixels(0.0, 0.2).is_empty());
        let ev = s.wheel_pixels(0.0, 0.2);
        assert_eq!(ev.len(), 1);
        assert_eq!(s.wheel_lines(0.0, 1.0).len(), 1);
    }

    #[test]
    fn point_mapping_with_letterbox_and_offset() {
        // 1000x500 window showing a 1920x1080 desktop letterboxed to 888x500 at x=56.
        let view = (56.0, 0.0, 888.0, 500.0);
        let src = (0.0, 0.0, 1920.0, 1080.0);
        assert_eq!(map_point(56.0, 0.0, view, src), Some((0, 0)));
        assert_eq!(map_point(944.0, 500.0, view, src), Some((1919, 1079)));
        assert_eq!(map_point(0.0, 250.0, view, src), Some((0, 540)), "clamped into the image");
        // Second monitor window shows desktop region starting at x=2560.
        assert_eq!(map_point(0.0, 0.0, (0.0, 0.0, 1920.0, 1080.0), (2560.0, 0.0, 1920.0, 1080.0)), Some((2560, 0)));
    }
}
