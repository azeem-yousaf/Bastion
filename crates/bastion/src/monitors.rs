//! Local monitors: which ones a session uses, and what to do when they are plugged in or out.
//!
//! Monitors are identified by their connector name (e.g. `DP-1`), which is stable across
//! reboots and replugging, so it can be saved in a profile. The decision logic is pure so it
//! can be unit-tested without a display.

use winit::event_loop::ActiveEventLoop;
use winit::monitor::MonitorHandle;

/// A local monitor as currently connected.
#[derive(Debug, Clone, PartialEq)]
pub struct Screen {
    /// Stable identifier (connector name), saved in profiles.
    pub key: String,
    /// Human-readable description, e.g. `DP-1 — 3840 × 2160`.
    pub label: String,
    pub handle: MonitorHandle,
}

/// The monitors connected right now, in the order the platform reports them.
pub fn snapshot(event_loop: &ActiveEventLoop) -> Vec<Screen> {
    let mut out: Vec<Screen> = Vec::new();
    for handle in event_loop.available_monitors() {
        let size = handle.size();
        let pos = handle.position();
        let mut key = handle.name().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| {
            // No connector name (rare): fall back to geometry, stable while nothing moves.
            format!("{}x{}@{},{}", size.width, size.height, pos.x, pos.y)
        });
        if out.iter().any(|s| s.key == key) {
            key = format!("{key}#{}", out.len() + 1);
        }
        let label = format!("{key} — {} × {}", size.width, size.height);
        out.push(Screen { key, label, handle });
    }
    out
}

pub fn keys(screens: &[Screen]) -> Vec<String> {
    screens.iter().map(|s| s.key.clone()).collect()
}

/// Whether the profile's selection allows a monitor (an empty selection means all monitors).
pub fn allowed(selection: &[String], key: &str) -> bool {
    selection.is_empty() || selection.iter().any(|s| s == key)
}

/// Monitors a multi-monitor session should use: the selected ones that are connected (in
/// connection order), or every connected monitor when the selection is empty or none of the
/// selected monitors is connected.
pub fn choose(present: &[String], selection: &[String]) -> Vec<String> {
    let picked: Vec<String> = present.iter().filter(|k| allowed(selection, k)).cloned().collect();
    if picked.is_empty() { present.to_vec() } else { picked }
}

/// What a session should do after the set of connected monitors changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Re-create the session's windows on exactly these monitors (one = single full screen).
    pub use_monitors: Option<Vec<String>>,
    /// Newly connected monitors to offer to the user.
    pub offer: Vec<String>,
}

/// Decides how a session reacts to a monitor change.
///
/// * `in_use`: monitors the session's full-screen windows are on (empty for a window).
/// * `before` / `now`: connected monitors before and after the change.
/// * `selection`: the profile's monitor selection (empty = all).
/// * `fullscreen`: whether the session is full screen (windowed sessions are never prompted).
///
/// Losing a monitor keeps the session on the remaining ones (single full screen when one is
/// left). New monitors the selection allows are offered, never added silently.
pub fn plan(in_use: &[String], before: &[String], now: &[String], selection: &[String], fullscreen: bool) -> Plan {
    let remaining: Vec<String> = in_use.iter().filter(|k| now.contains(k)).cloned().collect();
    let use_monitors = if remaining.len() < in_use.len() {
        if remaining.is_empty() {
            // The session's only monitor is gone: continue full screen on another one.
            choose(now, selection).into_iter().next().map(|k| vec![k])
        } else {
            Some(remaining)
        }
    } else {
        None
    };
    let kept: &[String] = use_monitors.as_deref().unwrap_or(in_use);
    let offer = if fullscreen {
        now.iter().filter(|k| !before.contains(k) && !kept.contains(k) && allowed(selection, k)).cloned().collect()
    } else {
        Vec::new()
    };
    Plan { use_monitors, offer }
}

/// Monitors to use after the user accepted the offered ones: the current ones plus the offered
/// ones that are still connected, in connection order.
pub fn accept(in_use: &[String], offered: &[String], now: &[String]) -> Vec<String> {
    now.iter().filter(|k| in_use.contains(k) || offered.contains(k)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn empty_selection_uses_every_monitor() {
        assert_eq!(choose(&v(&["DP-1", "DP-2", "HDMI-A-1"]), &[]), v(&["DP-1", "DP-2", "HDMI-A-1"]));
    }

    #[test]
    fn selection_picks_a_subset_in_connection_order() {
        let present = v(&["DP-1", "DP-2", "HDMI-A-1"]);
        assert_eq!(choose(&present, &v(&["HDMI-A-1", "DP-1"])), v(&["DP-1", "HDMI-A-1"]));
    }

    #[test]
    fn selection_with_nothing_connected_falls_back_to_all() {
        assert_eq!(choose(&v(&["eDP-1"]), &v(&["DP-1", "DP-2"])), v(&["eDP-1"]));
    }

    #[test]
    fn unplugging_one_of_three_keeps_the_other_two() {
        let p = plan(&v(&["DP-1", "DP-2", "DP-3"]), &v(&["DP-1", "DP-2", "DP-3"]), &v(&["DP-1", "DP-3"]), &[], true);
        assert_eq!(p, Plan { use_monitors: Some(v(&["DP-1", "DP-3"])), offer: vec![] });
    }

    #[test]
    fn unplugging_down_to_one_monitor_goes_single_full_screen() {
        let p = plan(&v(&["DP-1", "DP-2"]), &v(&["DP-1", "DP-2"]), &v(&["DP-1"]), &[], true);
        assert_eq!(p.use_monitors, Some(v(&["DP-1"])));
    }

    #[test]
    fn losing_the_only_monitor_moves_to_another() {
        let p = plan(&v(&["DP-2"]), &v(&["DP-1", "DP-2"]), &v(&["DP-1"]), &[], true);
        assert_eq!(p.use_monitors, Some(v(&["DP-1"])));
    }

    #[test]
    fn unplugging_an_unused_monitor_changes_nothing() {
        let p = plan(&v(&["DP-1", "DP-2"]), &v(&["DP-1", "DP-2", "DP-3"]), &v(&["DP-1", "DP-2"]), &[], true);
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn plugging_in_a_monitor_offers_it_to_full_screen_sessions() {
        let p = plan(&v(&["DP-1"]), &v(&["DP-1"]), &v(&["DP-1", "DP-2"]), &[], true);
        assert_eq!(p, Plan { use_monitors: None, offer: v(&["DP-2"]) });
    }

    #[test]
    fn windowed_sessions_are_not_prompted() {
        let p = plan(&[], &v(&["DP-1"]), &v(&["DP-1", "DP-2"]), &[], false);
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn monitors_excluded_by_the_selection_are_never_offered() {
        let p = plan(&v(&["DP-1"]), &v(&["DP-1"]), &v(&["DP-1", "HDMI-A-1"]), &v(&["DP-1", "DP-2"]), true);
        assert!(p.offer.is_empty());
        let p = plan(&v(&["DP-1"]), &v(&["DP-1"]), &v(&["DP-1", "DP-2"]), &v(&["DP-1", "DP-2"]), true);
        assert_eq!(p.offer, v(&["DP-2"]));
    }

    #[test]
    fn accepting_adds_offered_monitors_that_are_still_connected() {
        let now = v(&["DP-1", "DP-2", "DP-3"]);
        assert_eq!(accept(&v(&["DP-3"]), &v(&["DP-1", "HDMI-A-1"]), &now), v(&["DP-1", "DP-3"]));
    }
}
