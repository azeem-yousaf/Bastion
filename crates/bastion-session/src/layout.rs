//! Desktop/monitor layout as negotiated with the server.

use ironrdp_displaycontrol::pdu::{DeviceScaleFactor, DisplayControlMonitorLayout, MonitorLayoutEntry};
use ironrdp_pdu::gcc::{
    ClientMonitorData, ClientMonitorExtendedData, ExtendedMonitorInfo, Monitor, MonitorFlags, MonitorOrientation,
};

/// One remote monitor in virtual-desktop pixel coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorSpec {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    /// Desktop scale in percent (100..=500).
    pub scale: u32,
    pub primary: bool,
    pub physical_mm: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopLayout {
    pub monitors: Vec<MonitorSpec>,
}

impl DesktopLayout {
    pub fn single(width: u32, height: u32, scale: u32) -> Self {
        Self { monitors: vec![MonitorSpec { x: 0, y: 0, width, height, scale, primary: true, physical_mm: None }] }
    }

    /// Normalises so the primary monitor sits at (0,0), sizes are even and within RDP limits.
    pub fn normalized(&self) -> Self {
        let mut monitors = self.monitors.clone();
        if monitors.is_empty() {
            return Self::single(1024, 768, 100);
        }
        if !monitors.iter().any(|m| m.primary) {
            // No explicit primary: use the monitor at the desktop origin (KDE/Windows convention).
            let idx = monitors.iter().position(|m| m.x == 0 && m.y == 0).unwrap_or(0);
            monitors[idx].primary = true;
        }
        let mut seen_primary = false;
        for m in &mut monitors {
            if m.primary {
                m.primary = !seen_primary;
                seen_primary = true;
            }
        }
        let p = *monitors.iter().find(|m| m.primary).expect("primary exists");
        for m in &mut monitors {
            m.x -= p.x;
            m.y -= p.y;
            let (w, h) = MonitorLayoutEntry::adjust_display_size(m.width, m.height);
            m.width = w;
            m.height = h;
            m.scale = MonitorLayoutEntry::adjust_desktop_scale_factor(m.scale);
        }
        monitors.truncate(16);
        Self { monitors }
    }

    pub fn primary(&self) -> MonitorSpec {
        *self.monitors.iter().find(|m| m.primary).unwrap_or(&self.monitors[0])
    }

    /// Bounding box of all monitors: (left, top, width, height).
    pub fn bounds(&self) -> (i32, i32, u32, u32) {
        let l = self.monitors.iter().map(|m| m.x).min().unwrap_or(0);
        let t = self.monitors.iter().map(|m| m.y).min().unwrap_or(0);
        let r = self.monitors.iter().map(|m| m.x + m.width as i32).max().unwrap_or(0);
        let b = self.monitors.iter().map(|m| m.y + m.height as i32).max().unwrap_or(0);
        (l, t, (r - l) as u32, (b - t) as u32)
    }

    pub fn is_multi(&self) -> bool {
        self.monitors.len() > 1
    }

    /// GCC monitor data for the initial connection (only for multi-monitor).
    pub fn gcc_monitors(&self) -> Option<(ClientMonitorData, ClientMonitorExtendedData)> {
        if !self.is_multi() {
            return None;
        }
        let monitors = self
            .monitors
            .iter()
            .map(|m| Monitor {
                left: m.x,
                top: m.y,
                right: m.x + m.width as i32 - 1,
                bottom: m.y + m.height as i32 - 1,
                flags: if m.primary { MonitorFlags::PRIMARY } else { MonitorFlags::empty() },
            })
            .collect();
        let extended = self
            .monitors
            .iter()
            .map(|m| ExtendedMonitorInfo {
                physical_width: m.physical_mm.map_or(0, |p| p.0),
                physical_height: m.physical_mm.map_or(0, |p| p.1),
                orientation: MonitorOrientation::Landscape,
                desktop_scale_factor: m.scale,
                device_scale_factor: device_scale(m.scale),
            })
            .collect();
        Some((ClientMonitorData { monitors }, ClientMonitorExtendedData { extended_monitors_info: extended }))
    }

    /// Display Control layout for runtime changes.
    pub fn display_control(&self) -> Option<DisplayControlMonitorLayout> {
        let entries: Option<Vec<_>> = self
            .monitors
            .iter()
            .map(|m| {
                let e = if m.primary {
                    MonitorLayoutEntry::new_primary(m.width, m.height)
                } else {
                    MonitorLayoutEntry::new_secondary(m.width, m.height)
                }
                .ok()?
                .with_position(m.x, m.y)
                .ok()?
                .with_desktop_scale_factor(m.scale)
                .ok()?
                // Windows ignores the desktop scale unless the device scale is valid too
                // (MS-RDPEDISP 2.2.2.2.1); use the same mapping as the connection-time GCC data.
                .with_device_scale_factor(
                    DeviceScaleFactor::from_value(device_scale(m.scale))
                        .unwrap_or_else(|| DeviceScaleFactor::from_desktop_scale_factor(m.scale)),
                );
                Some(match m.physical_mm {
                    Some((w, h)) => e.clone().with_physical_dimensions(w, h).unwrap_or(e),
                    None => e,
                })
            })
            .collect();
        DisplayControlMonitorLayout::new(&entries?).ok()
    }
}

/// A local monitor as the desktop describes it: logical (compositor) placement plus real pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LocalMonitor {
    /// Logical (scaled) top-left, as arranged in the desktop's display settings.
    pub logical_x: i32,
    pub logical_y: i32,
    /// Real pixel size of the monitor's mode.
    pub width: u32,
    pub height: u32,
    /// Fractional scale (e.g. 1.65).
    pub scale: f64,
}

impl LocalMonitor {
    fn logical_w(&self) -> f64 {
        f64::from(self.width) / self.scale.max(0.1)
    }
    fn logical_h(&self) -> f64 {
        f64::from(self.height) / self.scale.max(0.1)
    }
}

/// Builds the remote layout for monitors with possibly different scale factors.
///
/// Logical coordinates (what the user arranged) cannot be mixed with pixel sizes when scales
/// differ, so monitors are packed edge-to-edge in pixels, preserving their left/right and
/// above/below relationships. The result always has touching, non-overlapping monitors, as
/// Windows requires. Output order matches input order.
pub fn pack_monitors(mons: &[LocalMonitor], follow_scale: bool) -> DesktopLayout {
    const EPS: f64 = 2.0;
    let n = mons.len();
    let mut px = vec![0i64; n];
    let mut py = vec![0i64; n];

    let overlap = |a0: f64, a1: f64, b0: f64, b1: f64| a0 < b1 - EPS && b0 < a1 - EPS;

    let mut by_x: Vec<usize> = (0..n).collect();
    by_x.sort_by(|&a, &b| mons[a].logical_x.cmp(&mons[b].logical_x));
    for &i in &by_x {
        let m = &mons[i];
        let (t0, t1) = (f64::from(m.logical_y), f64::from(m.logical_y) + m.logical_h());
        px[i] = by_x
            .iter()
            .copied()
            .filter(|&j| j != i)
            .filter(|&j| f64::from(mons[j].logical_x) + mons[j].logical_w() <= f64::from(m.logical_x) + EPS)
            .filter(|&j| {
                overlap(t0, t1, f64::from(mons[j].logical_y), f64::from(mons[j].logical_y) + mons[j].logical_h())
            })
            .map(|j| px[j] + i64::from(mons[j].width))
            .max()
            .unwrap_or(0);
    }
    let mut by_y: Vec<usize> = (0..n).collect();
    by_y.sort_by(|&a, &b| mons[a].logical_y.cmp(&mons[b].logical_y));
    for &i in &by_y {
        let m = &mons[i];
        let (l0, l1) = (f64::from(m.logical_x), f64::from(m.logical_x) + m.logical_w());
        py[i] = by_y
            .iter()
            .copied()
            .filter(|&j| j != i)
            .filter(|&j| f64::from(mons[j].logical_y) + mons[j].logical_h() <= f64::from(m.logical_y) + EPS)
            .filter(|&j| {
                overlap(l0, l1, f64::from(mons[j].logical_x), f64::from(mons[j].logical_x) + mons[j].logical_w())
            })
            .map(|j| py[j] + i64::from(mons[j].height))
            .max()
            .unwrap_or(0);
    }
    // Primary = the monitor at the logical origin (else the top-left-most).
    let primary = (0..n)
        .find(|&i| mons[i].logical_x == 0 && mons[i].logical_y == 0)
        .or_else(|| (0..n).min_by_key(|&i| (mons[i].logical_y, mons[i].logical_x)))
        .unwrap_or(0);
    let monitors = mons
        .iter()
        .enumerate()
        .map(|(i, m)| MonitorSpec {
            x: px[i] as i32,
            y: py[i] as i32,
            width: m.width,
            height: m.height,
            scale: if follow_scale { (m.scale * 100.0).round() as u32 } else { 100 },
            primary: i == primary,
            physical_mm: None,
        })
        .collect();
    DesktopLayout { monitors }.normalized()
}

pub fn device_scale(desktop_scale: u32) -> u32 {
    match desktop_scale {
        0..=124 => 100,
        125..=164 => 140,
        _ => 180,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_odd_sizes_and_primary_origin() {
        let l = DesktopLayout {
            monitors: vec![
                MonitorSpec { x: 2560, y: 0, width: 1921, height: 1080, scale: 100, primary: false, physical_mm: None },
                MonitorSpec { x: 0, y: 0, width: 2560, height: 1440, scale: 100, primary: false, physical_mm: None },
            ],
        }
        .normalized();
        assert!(!l.monitors[0].primary && l.monitors[1].primary);
        assert_eq!(l.monitors[0].width, 1920, "odd width rounded to even");
        assert_eq!(l.bounds(), (0, 0, 2560 + 1920, 1440));
    }

    #[test]
    fn only_one_primary_survives() {
        let m = MonitorSpec { x: 0, y: 0, width: 800, height: 600, scale: 100, primary: true, physical_mm: None };
        let l = DesktopLayout { monitors: vec![m, MonitorSpec { x: 800, ..m }] }.normalized();
        assert_eq!(l.monitors.iter().filter(|m| m.primary).count(), 1);
    }

    #[test]
    fn multi_monitor_produces_gcc_and_dc_layouts() {
        let l = DesktopLayout {
            monitors: vec![
                MonitorSpec {
                    x: 0,
                    y: 0,
                    width: 2560,
                    height: 1440,
                    scale: 100,
                    primary: true,
                    physical_mm: Some((597, 336)),
                },
                MonitorSpec { x: 2560, y: 0, width: 3840, height: 2160, scale: 165, primary: false, physical_mm: None },
            ],
        };
        let (gcc, ext) = l.gcc_monitors().unwrap();
        assert_eq!(gcc.monitors[1].left, 2560);
        assert_eq!(gcc.monitors[1].right, 2560 + 3839);
        assert_eq!(ext.extended_monitors_info.len(), 2);
        let dc = l.display_control().unwrap();
        assert_eq!(dc.monitors().len(), 2);
        // Runtime layout changes (e.g. a monitor plugged back in) must carry a valid device
        // scale, or Windows drops the HiDPI scale and the monitor comes back at 100 %.
        let scales: Vec<_> =
            dc.monitors().iter().map(|m| (m.desktop_scale_factor(), m.device_scale_factor())).collect();
        assert_eq!(
            scales,
            vec![
                (Some(100), Some(DeviceScaleFactor::Scale100Percent)),
                (Some(165), Some(DeviceScaleFactor::Scale180Percent)),
            ]
        );
        // Same device scale as the connection-time data.
        assert_eq!(ext.extended_monitors_info[1].device_scale_factor, 180);
        assert!(DesktopLayout::single(1920, 1080, 100).gcc_monitors().is_none());
    }

    fn mon(lx: i32, ly: i32, w: u32, h: u32, scale: f64) -> LocalMonitor {
        LocalMonitor { logical_x: lx, logical_y: ly, width: w, height: h, scale }
    }

    #[test]
    fn mixed_dpi_side_by_side_is_packed_in_pixels() {
        // The user's real setup: 1440p @100% left, 4K @165% right.
        let l = pack_monitors(&[mon(2560, 0, 3840, 2160, 1.65), mon(0, 0, 2560, 1440, 1.0)], true);
        assert_eq!(l.bounds(), (0, 0, 6400, 2160));
        assert_eq!((l.monitors[0].x, l.monitors[0].y, l.monitors[0].scale), (2560, 0, 165));
        assert!(l.monitors[1].primary && l.monitors[1].x == 0);
        assert!(l.display_control().is_some(), "layout must be valid for Display Control");
        assert!(l.gcc_monitors().is_some());
    }

    #[test]
    fn stacked_and_left_of_primary() {
        let l = pack_monitors(&[mon(0, 0, 1920, 1080, 1.0), mon(0, 1080, 1920, 1080, 1.0)], false);
        assert_eq!(l.monitors[1].y, 1080);
        // Monitor left of the primary ends up at negative x, still touching.
        let l = pack_monitors(&[mon(0, 0, 1920, 1080, 1.0), mon(-1280, 0, 2560, 1440, 2.0)], false);
        assert_eq!(l.monitors[1].x, -2560);
        assert_eq!(l.bounds().2, 1920 + 2560);
    }

    #[test]
    fn three_monitors_in_a_row() {
        let l = pack_monitors(
            &[mon(0, 0, 1920, 1080, 1.0), mon(1920, 0, 3840, 2160, 2.0), mon(3840, 0, 1920, 1080, 1.0)],
            true,
        );
        assert_eq!(l.monitors.iter().map(|m| m.x).collect::<Vec<_>>(), vec![0, 1920, 5760]);
        assert!(l.display_control().is_some());
    }
}
