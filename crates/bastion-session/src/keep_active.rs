//! "Keep active": after a period with no input sent to the session, nudge the remote mouse by
//! one pixel and back so Windows (and presence-aware apps like Teams, which read the system idle
//! time) don't consider the user away.
//!
//! The nudge ends where it started, so the remote cursor doesn't drift. Real user input resets
//! the timer, so it never fights the user.

use std::time::Duration;

use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};
use smallvec::SmallVec;
use tokio::time::Instant;

#[derive(Debug)]
pub(crate) struct KeepActive {
    interval: Duration,
    deadline: Instant,
    /// Last known remote cursor position (from our own input or the server).
    pos: Option<(u16, u16)>,
}

impl KeepActive {
    pub(crate) fn new(interval: Duration, now: Instant) -> Self {
        Self { interval, deadline: now + interval, pos: None }
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Real input was sent: remember the cursor position and restart the idle timer.
    pub(crate) fn on_input(&mut self, events: &[FastPathInputEvent], now: Instant) {
        for e in events {
            match e {
                FastPathInputEvent::MouseEvent(m) => self.pos = Some((m.x_position, m.y_position)),
                FastPathInputEvent::MouseEventEx(m) => self.pos = Some((m.x_position, m.y_position)),
                _ => {}
            }
        }
        self.deadline = now + self.interval;
    }

    /// The server moved the cursor (doesn't count as user activity).
    pub(crate) fn on_server_pointer(&mut self, x: u16, y: u16) {
        self.pos = Some((x, y));
    }

    /// The idle deadline passed: returns the input to send and schedules the next nudge.
    pub(crate) fn nudge(&mut self, desktop: (u16, u16), now: Instant) -> SmallVec<[FastPathInputEvent; 2]> {
        self.deadline = now + self.interval;
        let (w, h) = (desktop.0.max(2), desktop.1.max(1));
        let (x, y) = self.pos.unwrap_or((w / 2, h / 2));
        let (x, y) = (x.min(w - 1), y.min(h - 1));
        // Step inward so we never push against the screen edge.
        let away = if x + 1 < w { x + 1 } else { x - 1 };
        self.pos = Some((x, y));
        SmallVec::from_buf([mouse_move(away, y), mouse_move(x, y)])
    }
}

fn mouse_move(x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::MouseEvent(MousePdu {
        flags: PointerFlags::MOVE,
        number_of_wheel_rotation_units: 0,
        x_position: x,
        y_position: y,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moves(events: &[FastPathInputEvent]) -> Vec<(u16, u16)> {
        events
            .iter()
            .map(|e| match e {
                FastPathInputEvent::MouseEvent(m) if m.flags == PointerFlags::MOVE => (m.x_position, m.y_position),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[test]
    fn input_resets_the_timer_and_tracks_position() {
        let t0 = Instant::now();
        let mut k = KeepActive::new(Duration::from_secs(30), t0);
        assert_eq!(k.deadline(), t0 + Duration::from_secs(30));
        let t1 = t0 + Duration::from_secs(20);
        k.on_input(&[mouse_move(100, 200)], t1);
        assert_eq!(k.deadline(), t1 + Duration::from_secs(30));
        let t2 = k.deadline();
        assert_eq!(moves(&k.nudge((1920, 1080), t2)), [(101, 200), (100, 200)]);
        // Keeps nudging every interval while idle.
        assert_eq!(k.deadline(), t2 + Duration::from_secs(30));
    }

    #[test]
    fn keyboard_input_also_counts_as_activity() {
        let t0 = Instant::now();
        let mut k = KeepActive::new(Duration::from_secs(60), t0);
        let t1 = t0 + Duration::from_secs(59);
        k.on_input(
            &[FastPathInputEvent::KeyboardEvent(ironrdp_pdu::input::fast_path::KeyboardFlags::empty(), 0x1e)],
            t1,
        );
        assert_eq!(k.deadline(), t1 + Duration::from_secs(60));
    }

    #[test]
    fn unknown_position_uses_centre_and_edges_step_inward() {
        let t0 = Instant::now();
        let mut k = KeepActive::new(Duration::from_secs(30), t0);
        assert_eq!(moves(&k.nudge((1920, 1080), t0)), [(961, 540), (960, 540)]);
        k.on_server_pointer(1919, 5);
        assert_eq!(moves(&k.nudge((1920, 1080), t0)), [(1918, 5), (1919, 5)]);
        // Position beyond a (shrunk) desktop is clamped.
        k.on_server_pointer(5000, 5000);
        assert_eq!(moves(&k.nudge((800, 600), t0)), [(798, 599), (799, 599)]);
    }
}
