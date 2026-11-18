//! A live remote session and the window(s) showing it.
//!
//! One window normally; in "all monitors" mode one borderless fullscreen window per local
//! monitor, each showing its slice of the remote virtual desktop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion_core::profile::{DisplayMode, Profile};
use bastion_session::tls::CertificateRejection;
use bastion_session::{Command, DesktopLayout, Event, PointerEvent, SessionHandle, Status};
use ironrdp_input::MouseButton;
use winit::event::{ElementState, MouseScrollDelta, WindowEvent};
use winit::event_loop::ActiveEventLoop;
use winit::keyboard::PhysicalKey;
use winit::platform::scancode::PhysicalKeyExtScancode as _;
use winit::platform::wayland::WindowAttributesExtWayland as _;
use winit::window::{CursorIcon, CustomCursor, Fullscreen, Window, WindowId};

use crate::gpu::{Gpu, WindowGfx};
use crate::input::{Events, InputState, KeyOutcome, map_point};
use crate::monitors::{self, Screen};
use crate::theme;

pub struct View {
    /// Declared first: must be dropped before the window it refers to.
    inhibitor: Option<crate::inhibit::ShortcutInhibitor>,
    pub gfx: WindowGfx,
    /// Remote-desktop region shown by this window (x, y, w, h). `None` = whole desktop.
    region: Option<(u32, u32, u32, u32)>,
    tex_id: Option<egui::TextureId>,
    /// Where the image was drawn last frame (window physical pixels).
    image_rect: Option<(f64, f64, f64, f64)>,
    pointer_in_ui: bool,
    bar: BarState,
    /// Where the session bar was drawn last frame (points).
    bar_rect: Option<egui::Rect>,
    /// Where the "new monitor" prompt was drawn last frame (points).
    prompt_rect: Option<egui::Rect>,
    /// Full-screen state this window should have. Compositors drop full screen when a window is
    /// minimised (however that happens), so it is re-applied whenever the window regains focus.
    want_fullscreen: Option<Fullscreen>,
    /// Minimised via the session bar (so sibling monitor windows are restored together).
    minimized: bool,
}

enum Phase {
    Connecting(String),
    Connected,
    Reconnecting(String),
    Disconnected { reason: String, error: bool },
}

pub struct Session {
    pub profile: Profile,
    pub handle: SessionHandle,
    pub views: HashMap<WindowId, View>,
    phase: Phase,
    /// Pending certificate prompt: the rejection, the "I have verified it" tick, and when the
    /// dialog was first painted (its trust button stays disabled for [`CERT_ARM_DELAY`]).
    cert: Option<(Box<CertificateRejection>, bool, Option<Instant>)>,
    /// Set when Bastion itself ended the session (e.g. a desktop size the GPU cannot show);
    /// this message is kept over whatever the engine reports afterwards.
    fatal: Option<String>,
    notices: Vec<(Instant, String)>,
    input: InputState,
    /// Keyboard goes to the remote session (false after the release chord until clicked back).
    grabbed: bool,
    texture: Option<(wgpu::Texture, wgpu::TextureView, u64)>,
    cursor_cache: HashMap<usize, CustomCursor>,
    remote_cursor: RemoteCursor,
    pending_layout: Option<(Instant, DesktopLayout)>,
    pub want_close: bool,
    /// Ask the app to reconnect with the same parameters.
    pub want_reconnect: bool,
    /// Window title shared by all of this session's windows (used to find them in KWin).
    title: String,
    last_sibling_restore: Option<Instant>,
    /// User setting: forward Alt+Tab/Super etc. to the remote computer.
    grab_shortcuts: bool,
    /// The user pinned the session bar (kept visible on one window).
    pin_bar: bool,
    /// Window the bar was pinned on (defaults to the one showing the desktop's top-left).
    pin_window: Option<WindowId>,
    /// The user pinned or unpinned the bar; the app saves it as the default for new sessions.
    pub pin_changed: Option<bool>,
    /// Set when sign-in failed, so a remembered (wrong) password is discarded.
    pub auth_failed: bool,
    /// Monitors (keys) the full-screen windows were created on; empty for a window or a
    /// single full screen on "the current monitor".
    in_use: Vec<String>,
    /// Newly connected monitors offered to the user: (key, label).
    offer: Vec<(String, String)>,
    /// The user accepted the offer; applied by `apply_monitor_changes`.
    want_extend: bool,
    /// Monitors to move the session to; applied by `apply_monitor_changes`.
    pending_monitors: Option<Vec<String>>,
    /// Layout after a monitor change, re-sent after a reconnect (which uses the old one).
    rebuilt_layout: Option<DesktopLayout>,
    /// Connection quality indicator (sampled while connected).
    quality: crate::quality::Meter,
    next_quality_sample: Option<Instant>,
    /// Monitors the session was full screen on before the user chose "Exit full screen"
    /// (empty = single full screen on the current monitor), restored by "Full screen".
    restore_fullscreen: Option<Vec<String>>,
    /// Full-screen switch that needs new windows; applied by `apply_monitor_changes`.
    pending_switch: Option<Switch>,
}

/// A full-screen switch from the session bar that re-creates the session's windows.
enum Switch {
    /// Leave multi-monitor full screen for one ordinary window.
    Windowed,
    /// Go back to full screen on these monitors (those still connected).
    Fullscreen(Vec<String>),
}

/// Which windows a session shows.
enum Target {
    Window,
    /// One full-screen window; `None` = whichever monitor the compositor picks.
    Fullscreen(Option<Screen>),
    /// One full-screen window per monitor (at least two).
    Monitors(Vec<Screen>),
}

impl Target {
    fn from_keys(screens: &[Screen], keys: &[String]) -> Self {
        let mut chosen: Vec<Screen> = screens.iter().filter(|s| keys.contains(&s.key)).cloned().collect();
        match chosen.len() {
            0 => Target::Window,
            1 => Target::Fullscreen(chosen.pop()),
            _ => Target::Monitors(chosen),
        }
    }
}

struct Built {
    views: HashMap<WindowId, View>,
    layout: DesktopLayout,
    in_use: Vec<String>,
}

impl View {
    fn new(gfx: WindowGfx, region: Option<(u32, u32, u32, u32)>, want_fullscreen: Option<Fullscreen>) -> Self {
        Self {
            inhibitor: None,
            gfx,
            region,
            tex_id: None,
            image_rect: None,
            pointer_in_ui: false,
            bar: BarState::Hidden,
            bar_rect: None,
            prompt_rect: None,
            want_fullscreen,
            minimized: false,
        }
    }
}

/// Creates the window(s) for `target` and the matching remote desktop layout.
fn build(
    event_loop: &ActiveEventLoop,
    gpu: &Gpu,
    title: &str,
    profile: &Profile,
    target: Target,
) -> anyhow::Result<Built> {
    let follow_scale = profile.display.follow_local_scale;
    let base = || Window::default_attributes().with_title(title.to_owned()).with_name("bastion", "bastion");
    let mut views = HashMap::new();
    match target {
        Target::Monitors(screens) => {
            // Create one fullscreen window per monitor first: the window knows the true
            // fractional scale (e.g. 165%), the monitor handle only the rounded one.
            let mut windows = Vec::new();
            for s in &screens {
                let attrs = base().with_fullscreen(Some(Fullscreen::Borderless(Some(s.handle.clone()))));
                windows.push(Arc::new(event_loop.create_window(attrs)?));
            }
            let locals: Vec<_> = screens
                .iter()
                .map(|s| {
                    // winit reports logical position x integer output scale; undo that.
                    let m = &s.handle;
                    let sc = m.scale_factor().max(1.0);
                    let pos = m.position();
                    bastion_session::LocalMonitor {
                        logical_x: (f64::from(pos.x) / sc).round() as i32,
                        logical_y: (f64::from(pos.y) / sc).round() as i32,
                        width: m.size().width,
                        height: m.size().height,
                        scale: sc,
                    }
                })
                .collect();
            let mut layout = bastion_session::pack_monitors(&locals, follow_scale);
            if follow_scale {
                for (spec, w) in layout.monitors.iter_mut().zip(&windows) {
                    spec.scale = (w.scale_factor() * 100.0).round() as u32;
                }
                layout = layout.normalized();
            }
            tracing::info!(?layout, "Multi-monitor layout");
            let (bx, by, _, _) = layout.bounds();
            for ((window, spec), s) in windows.into_iter().zip(&layout.monitors).zip(&screens) {
                let region = ((spec.x - bx) as u32, (spec.y - by) as u32, spec.width, spec.height);
                let gfx = WindowGfx::new(gpu, window.clone(), None)?;
                let fs = Some(Fullscreen::Borderless(Some(s.handle.clone())));
                views.insert(window.id(), View::new(gfx, Some(region), fs));
            }
            Ok(Built { views, layout, in_use: screens.into_iter().map(|s| s.key).collect() })
        }
        Target::Fullscreen(screen) => {
            let fs = Fullscreen::Borderless(screen.as_ref().map(|s| s.handle.clone()));
            let attrs = base()
                .with_inner_size(winit::dpi::LogicalSize::new(profile.display.width, profile.display.height))
                .with_min_inner_size(winit::dpi::LogicalSize::new(320, 240))
                .with_fullscreen(Some(fs.clone()));
            let window = Arc::new(event_loop.create_window(attrs)?);
            // A known monitor gives the real size; otherwise the window's (corrected on resize).
            let size = screen.as_ref().map_or_else(|| window.inner_size(), |s| s.handle.size());
            let scale = if follow_scale { (window.scale_factor() * 100.0).round() as u32 } else { 100 };
            let gfx = WindowGfx::new(gpu, window.clone(), None)?;
            views.insert(window.id(), View::new(gfx, None, Some(fs)));
            let layout = DesktopLayout::single(size.width.max(640), size.height.max(480), scale);
            Ok(Built { views, layout, in_use: screen.into_iter().map(|s| s.key).collect() })
        }
        Target::Window => {
            let attrs = base()
                .with_inner_size(winit::dpi::LogicalSize::new(profile.display.width, profile.display.height))
                .with_min_inner_size(winit::dpi::LogicalSize::new(320, 240));
            let window = Arc::new(event_loop.create_window(attrs)?);
            let size = window.inner_size();
            let scale = if follow_scale { (window.scale_factor() * 100.0).round() as u32 } else { 100 };
            let gfx = WindowGfx::new(gpu, window.clone(), None)?;
            views.insert(window.id(), View::new(gfx, None, None));
            let layout = DesktopLayout::single(size.width.max(640), size.height.max(480), scale);
            Ok(Built { views, layout, in_use: Vec::new() })
        }
    }
}

#[derive(Clone)]
enum RemoteCursor {
    Default,
    Hidden,
    Custom(CustomCursor),
}

const RESIZE_DEBOUNCE: Duration = Duration::from_millis(300);
/// How long the certificate dialog's trust button stays disabled after the dialog first appears.
/// The prompt can pop up in the middle of work (an automatic reconnect), so a click that was
/// already on its way to the remote desktop must not be able to accept a certificate.
pub const CERT_ARM_DELAY: Duration = Duration::from_millis(1500);

/// Whether the certificate dialog's trust button may be used, `shown_for` after it appeared.
pub fn cert_armed(shown_for: Duration) -> bool {
    shown_for >= CERT_ARM_DELAY
}

/// Whether egui may see this window event of a session window. Keyboard and IME input never
/// does: no session overlay has a text field, and egui would otherwise let Tab focus an overlay
/// button and Space/Enter "click" it — keys typed for the remote computer could accept a
/// certificate or disconnect. Overlays are operated with the pointer only.
pub fn egui_may_see(event: &WindowEvent) -> bool {
    !matches!(event, WindowEvent::KeyboardInput { .. } | WindowEvent::Ime(_))
}

/// Second line of defence, called at the start of every session-window frame: drops any
/// keyboard input that reached egui anyway and takes keyboard focus away from overlay widgets,
/// so nothing in a session window can be activated from the keyboard.
pub fn isolate_keyboard(ctx: &egui::Context) {
    ctx.input_mut(|i| {
        i.events.retain(|e| {
            !matches!(
                e,
                egui::Event::Key { .. }
                    | egui::Event::Text(_)
                    | egui::Event::Ime(_)
                    | egui::Event::Copy
                    | egui::Event::Cut
                    | egui::Event::Paste(_)
            )
        });
        i.keys_down.clear();
    });
    ctx.memory_mut(|m| {
        if let Some(id) = m.focused() {
            m.surrender_focus(id);
        }
    });
}

/// Checks a desktop size chosen by the remote computer against what the GPU can hold in one
/// texture (`max_side`). The error is shown to the user as the reason the session ended.
pub fn check_desktop_size(width: u32, height: u32, max_side: u32) -> Result<(), String> {
    if crate::gpu::texture_size_ok(width, height, max_side) {
        return Ok(());
    }
    Err(format!(
        "The remote computer asked for a screen of {width} × {height} pixels, which is more than this \
         computer's graphics hardware can display (at most {max_side} × {max_side}). The session was closed."
    ))
}
/// Events egui reports as "needs repaint" that must not schedule one: egui says so for
/// `RedrawRequested` itself, so honouring it re-requested a frame after every frame and each
/// visible window rendered at the monitor refresh rate forever (~300 frames/s over two
/// monitors).
pub fn is_redraw_echo(event: &WindowEvent) -> bool {
    matches!(event, WindowEvent::RedrawRequested)
}

/// Session-bar visibility for one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarState {
    Hidden,
    /// Revealed by touching the top-centre edge; hides again when the pointer leaves.
    Hover,
    /// Shown deliberately (keyboard released with Ctrl+Alt+Home); stays until dismissed.
    Pinned,
}

/// Half-width (points) of the top-edge zone that reveals the bar — away from the corners,
/// where remote windows have their close/minimise buttons.
const REVEAL_HALF_WIDTH: f32 = 220.0;
/// How far below the bar the pointer may go before a hover-revealed bar hides.
const HIDE_MARGIN: f32 = 30.0;

/// Decides the bar state after a pointer move (all coordinates in points). Returns the new
/// state and whether the pointer is over the bar (so input goes to the bar, not the remote).
pub fn bar_on_pointer(
    state: BarState,
    pointer: egui::Pos2,
    window_width: f32,
    fullscreen: bool,
    bar_rect: Option<egui::Rect>,
) -> (BarState, bool) {
    let over_bar = state != BarState::Hidden && bar_rect.is_some_and(|r| r.expand(2.0).contains(pointer));
    let in_reveal_zone = fullscreen && pointer.y <= 1.5 && (pointer.x - window_width / 2.0).abs() <= REVEAL_HALF_WIDTH;
    let next = match state {
        BarState::Hidden if in_reveal_zone => BarState::Hover,
        BarState::Hover => {
            let bottom = bar_rect.map_or(40.0, |r| r.bottom());
            if !over_bar && !in_reveal_zone && pointer.y > bottom + HIDE_MARGIN {
                BarState::Hidden
            } else {
                BarState::Hover
            }
        }
        other => other,
    };
    (next, over_bar)
}

impl Session {
    /// Creates the session's window(s) and starts connecting.
    pub fn open(
        event_loop: &ActiveEventLoop,
        gpu: &Gpu,
        profile: Profile,
        screens: &[Screen],
        params_without_layout: impl FnOnce(DesktopLayout) -> bastion_session::ConnectParams,
        waker: bastion_session::Waker,
        settings: &bastion_core::store::AppSettings,
    ) -> anyhow::Result<Self> {
        let title = format!("{} — Bastion", profile.display_name());
        let mut notices = Vec::new();
        let target = match profile.display.mode {
            DisplayMode::Window => Target::Window,
            DisplayMode::Fullscreen => Target::Fullscreen(None),
            DisplayMode::AllMonitors => {
                let selection = &profile.display.monitors;
                let chosen = monitors::choose(&monitors::keys(screens), selection);
                let missing: Vec<&str> = selection.iter().filter(|k| !chosen.contains(k)).map(String::as_str).collect();
                if !missing.is_empty() && !chosen.is_empty() {
                    tracing::info!(?missing, ?chosen, "Selected monitors not connected");
                    notices.push((Instant::now(), format!("Not connected: {}", missing.join(", "))));
                }
                Target::from_keys(screens, &chosen)
            }
        };
        let built = build(event_loop, gpu, &title, &profile, target)?;
        let handle = SessionHandle::spawn(params_without_layout(built.layout.clone()), waker);
        Ok(Self {
            profile,
            handle,
            views: built.views,
            phase: Phase::Connecting("Starting…".into()),
            cert: None,
            fatal: None,
            notices,
            input: InputState::new(),
            grabbed: true,
            texture: None,
            cursor_cache: HashMap::new(),
            remote_cursor: RemoteCursor::Default,
            pending_layout: None,
            want_close: false,
            want_reconnect: false,
            auth_failed: false,
            grab_shortcuts: settings.grab_system_shortcuts,
            pin_bar: settings.pin_session_bar,
            pin_window: None,
            pin_changed: None,
            title,
            last_sibling_restore: None,
            in_use: built.in_use,
            offer: Vec::new(),
            want_extend: false,
            pending_monitors: None,
            rebuilt_layout: None,
            quality: crate::quality::Meter::default(),
            next_quality_sample: None,
            restore_fullscreen: None,
            pending_switch: None,
        })
    }

    /// Full-screen monitors this session is on right now (empty for a windowed session).
    fn monitors_in_use(&self, screens: &[Screen]) -> Vec<String> {
        if !self.in_use.is_empty() {
            return self.in_use.clone();
        }
        // Single full screen on "the current monitor": ask where the window is.
        self.views
            .values()
            .filter(|v| v.want_fullscreen.is_some())
            .filter_map(|v| v.gfx.window.current_monitor())
            .filter_map(|m| screens.iter().find(|s| s.handle == m).map(|s| s.key.clone()))
            .collect()
    }

    fn is_fullscreen(&self) -> bool {
        self.views.values().any(|v| v.want_fullscreen.is_some())
    }

    /// Reacts to monitors being plugged in or out (`before` = previously connected keys).
    pub fn monitors_changed(&mut self, before: &[String], screens: &[Screen]) {
        let now = monitors::keys(screens);
        let in_use = self.monitors_in_use(screens);
        let plan = monitors::plan(&in_use, before, &now, &self.profile.display.monitors, self.is_fullscreen());
        tracing::info!(?before, ?now, ?in_use, ?plan, "Monitors changed");
        self.offer.retain(|(k, _)| now.contains(k));
        for k in plan.offer {
            if !self.offer.iter().any(|(o, _)| *o == k)
                && let Some(s) = screens.iter().find(|s| s.key == k)
            {
                self.offer.push((k, s.label.clone()));
            }
        }
        if let Some(keys) = plan.use_monitors {
            self.offer.retain(|(k, _)| !keys.contains(k));
            self.pending_monitors = Some(keys);
        }
        self.request_redraw();
    }

    /// Applies a pending monitor change (a monitor was unplugged, or the user accepted a new
    /// one). Needs the event loop to create windows, so the app calls it between events.
    pub fn apply_monitor_changes(&mut self, event_loop: &ActiveEventLoop, gpu: &Gpu, screens: &[Screen]) {
        match self.pending_switch.take() {
            Some(Switch::Windowed) => {
                self.offer.clear();
                self.pending_monitors = None;
                self.reconfigure(event_loop, gpu, Target::Window);
                return;
            }
            Some(Switch::Fullscreen(keys)) => {
                let target = match Target::from_keys(screens, &keys) {
                    // None of those monitors is connected any more: full screen where the window is.
                    Target::Window => Target::Fullscreen(None),
                    t => t,
                };
                self.reconfigure(event_loop, gpu, target);
                return;
            }
            None => {}
        }
        if std::mem::take(&mut self.want_extend) {
            let now = monitors::keys(screens);
            let offered: Vec<String> = self.offer.drain(..).map(|(k, _)| k).collect();
            let in_use = self.monitors_in_use(screens);
            self.pending_monitors = Some(monitors::accept(&in_use, &offered, &now));
        }
        let Some(keys) = self.pending_monitors.take() else { return };
        let target = Target::from_keys(screens, &keys);
        if matches!(target, Target::Window) {
            return;
        }
        let lost = keys.len() < self.in_use.len();
        self.reconfigure(event_loop, gpu, target);
        if lost {
            let msg = match self.in_use.as_slice() {
                [one] => format!("A monitor was disconnected. Now full screen on {one}."),
                many => format!("A monitor was disconnected. Now using {} monitors.", many.len()),
            };
            self.notices.push((Instant::now(), msg));
        }
    }

    /// Re-creates the session's windows for a new monitor arrangement and tells the remote
    /// computer about the new layout. The connection itself is kept.
    fn reconfigure(&mut self, event_loop: &ActiveEventLoop, gpu: &Gpu, target: Target) {
        let ev = self.input.release_all();
        self.send(ev);
        match build(event_loop, gpu, &self.title, &self.profile, target) {
            Ok(built) => {
                tracing::info!(layout = ?built.layout, monitors = ?built.in_use, "Session moved to new monitors");
                // Old windows (and their GPU surfaces) are dropped here.
                self.views = built.views;
                self.in_use = built.in_use;
                self.texture = None;
                self.pending_layout = None;
                self.handle.send(Command::Layout(built.layout.clone()));
                self.rebuilt_layout = Some(built.layout);
                self.apply_cursor(self.remote_cursor.clone());
                self.request_redraw();
            }
            Err(e) => tracing::error!(error = %e, "Could not move the session to the new monitors"),
        }
    }

    pub fn owns(&self, id: WindowId) -> bool {
        self.views.contains_key(&id)
    }

    fn send(&self, ev: Events) {
        if !ev.is_empty() {
            self.handle.send(Command::Input(ev));
        }
    }

    fn connected(&self) -> bool {
        matches!(self.phase, Phase::Connected)
    }

    fn modal_open(&self) -> bool {
        self.cert.is_some() || !self.connected()
    }

    /// Drains engine events. Returns true if anything changed.
    pub fn poll(&mut self, event_loop: &ActiveEventLoop) -> bool {
        let mut changed = false;
        while let Some(ev) = self.handle.try_event() {
            changed = true;
            match ev {
                // Once Bastion has ended the session, late status updates must not revive it.
                Event::Status(_) if self.fatal.is_some() => {}
                Event::Status(s) => {
                    self.phase = match s {
                        Status::ConnectingGateway => Phase::Connecting("Connecting to RD Gateway…".into()),
                        Status::Connecting => Phase::Connecting("Connecting to remote computer…".into()),
                        Status::Authenticating => Phase::Connecting("Signing in…".into()),
                        Status::Waking => {
                            Phase::Connecting("Waking the remote computer… (this can take a minute)".into())
                        }
                        Status::Connected { .. } => Phase::Connected,
                        Status::Reconnecting { attempt, max } => {
                            Phase::Reconnecting(format!("Connection lost. Reconnecting (attempt {attempt} of {max})…"))
                        }
                    };
                    if self.connected() {
                        self.quality.reset();
                        self.next_quality_sample = Some(Instant::now());
                        let locks = bastion_session::keyboard::read_lock_state();
                        self.send(self.input.sync_locks(locks));
                        // A reconnect starts with the original layout; restore the monitor
                        // arrangement chosen since (the engine ignores an unchanged layout).
                        if let Some(l) = &self.rebuilt_layout {
                            self.handle.send(Command::Layout(l.clone()));
                        }
                    }
                }
                Event::Pointer(p) => self.set_remote_cursor(event_loop, p),
                Event::CertificatePrompt(_) if self.fatal.is_some() => {}
                Event::CertificatePrompt(r) => self.cert = Some((r, false, None)),
                Event::Notice(n) => self.notices.push((Instant::now(), n)),
                Event::Disconnected { reason, error } => {
                    if reason.starts_with("Sign-in failed") || reason.contains("rejected your credentials") {
                        self.auth_failed = true;
                    }
                    if !error
                        && matches!(self.phase, Phase::Connected | Phase::Connecting(_))
                        && reason == "Disconnected."
                    {
                        self.want_close = true;
                    }
                    self.phase = match &self.fatal {
                        Some(fatal) => Phase::Disconnected { reason: fatal.clone(), error: true },
                        None => Phase::Disconnected { reason, error },
                    };
                    self.cert = None;
                    self.apply_cursor(RemoteCursor::Default);
                }
            }
        }
        if let Some((at, layout)) = &self.pending_layout
            && at.elapsed() >= RESIZE_DEBOUNCE
        {
            self.handle.send(Command::Layout(layout.clone()));
            self.pending_layout = None;
        }
        changed |= self.sample_quality();
        let before = self.notices.len();
        self.notices.retain(|(t, _)| t.elapsed() < Duration::from_secs(8));
        // An expired notice must be painted away (nothing else may trigger a redraw).
        changed |= self.notices.len() != before;
        if changed {
            bastion_metrics::UI_REDRAW_ENGINE.incr();
            self.request_redraw();
        }
        changed
    }

    /// Samples the connection about once a second. Returns true when the indicator is visible
    /// and its figures changed, or a warning was raised.
    fn sample_quality(&mut self) -> bool {
        if !self.connected() {
            self.next_quality_sample = None;
            return false;
        }
        let now = Instant::now();
        if self.next_quality_sample.is_some_and(|t| now < t) {
            return false;
        }
        self.next_quality_sample = Some(now + crate::quality::SAMPLE_INTERVAL);
        let update = self.quality.update(now, self.handle.link.sample(&self.handle.frame));
        if let Some(w) = &update.warning {
            if let Some(q) = &self.quality.current {
                tracing::warn!(
                    latency_ms = ?q.latency_ms,
                    source = ?q.latency_source,
                    loss_pct = ?q.loss_pct,
                    "Poor connection"
                );
            }
            self.notices.push((now, w.clone()));
        }
        let visible = self.views.values().any(|v| v.bar != BarState::Hidden);
        (update.changed && visible) || update.warning.is_some()
    }

    pub fn next_deadline(&mut self) -> Option<Instant> {
        let mut d = self.pending_layout.as_ref().map(|(t, _)| *t + RESIZE_DEBOUNCE);
        if let Some(t) = self.next_quality_sample {
            d = Some(d.map_or(t, |x| x.min(t)));
        }
        for v in self.views.values_mut() {
            if let Some(t) = v.gfx.tick() {
                d = Some(d.map_or(t, |x| x.min(t)));
            }
        }
        if let Some((t, _)) = self.notices.first() {
            let n = *t + Duration::from_secs(8);
            d = Some(d.map_or(n, |x| x.min(n)));
        }
        d
    }

    pub fn request_redraw(&self) {
        for v in self.views.values() {
            v.gfx.window.request_redraw();
        }
    }

    fn set_remote_cursor(&mut self, event_loop: &ActiveEventLoop, p: PointerEvent) {
        let c = match p {
            PointerEvent::Default => RemoteCursor::Default,
            PointerEvent::Hidden => RemoteCursor::Hidden,
            PointerEvent::Position { .. } => return,
            PointerEvent::Bitmap(bmp) => {
                let key = Arc::as_ptr(&bmp) as usize;
                if let Some(c) = self.cursor_cache.get(&key) {
                    RemoteCursor::Custom(c.clone())
                } else {
                    match CustomCursor::from_rgba(
                        bmp.bitmap_data.clone(),
                        bmp.width,
                        bmp.height,
                        bmp.hotspot_x,
                        bmp.hotspot_y,
                    ) {
                        Ok(src) => {
                            let c = event_loop.create_custom_cursor(src);
                            if self.cursor_cache.len() > 64 {
                                self.cursor_cache.clear();
                            }
                            self.cursor_cache.insert(key, c.clone());
                            RemoteCursor::Custom(c)
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "Invalid remote cursor");
                            RemoteCursor::Default
                        }
                    }
                }
            }
        };
        self.remote_cursor = c.clone();
        self.apply_cursor(c);
    }

    fn apply_cursor(&self, c: RemoteCursor) {
        for v in self.views.values() {
            if v.pointer_in_ui || self.modal_open() {
                v.gfx.window.set_cursor_visible(true);
                v.gfx.window.set_cursor(CursorIcon::Default);
                continue;
            }
            match &c {
                RemoteCursor::Default => {
                    v.gfx.window.set_cursor_visible(true);
                    v.gfx.window.set_cursor(CursorIcon::Default);
                }
                RemoteCursor::Hidden => v.gfx.window.set_cursor_visible(false),
                RemoteCursor::Custom(cc) => {
                    v.gfx.window.set_cursor_visible(true);
                    v.gfx.window.set_cursor(cc.clone());
                }
            }
        }
    }

    /// Handles a window event for one of this session's windows.
    pub fn window_event(&mut self, gpu: &Gpu, id: WindowId, event: &WindowEvent) {
        let pinned_here = self.pinned_view() == Some(id);
        let Some(view) = self.views.get_mut(&id) else { return };
        if pinned_here {
            view.bar = BarState::Pinned;
        }
        // Keyboard input is never given to egui (see `egui_may_see`); whether a key goes to the
        // remote computer is decided below from our own state only.
        let egui_resp = if egui_may_see(event) {
            view.gfx.egui.on_window_event(&view.gfx.window, event)
        } else {
            egui_winit::EventResponse { consumed: false, repaint: false }
        };
        let modal = self.cert.is_some() || !matches!(self.phase, Phase::Connected);
        // egui asks to repaint on every pointer move; that only matters while one of our
        // overlays is on screen — new remote pixels trigger their own redraw.
        let overlay = modal
            || view.bar != BarState::Hidden
            || view.prompt_rect.is_some()
            || !self.notices.is_empty()
            || !self.grabbed;
        if egui_resp.repaint && !is_redraw_echo(event) && (overlay || !matches!(event, WindowEvent::CursorMoved { .. }))
        {
            bastion_metrics::UI_REDRAW_INPUT.incr();
            view.gfx.window.request_redraw();
        }

        match event {
            WindowEvent::CloseRequested => {
                self.handle.send(Command::Disconnect);
                self.want_close = true;
            }
            WindowEvent::Resized(size) => {
                view.gfx.resize(gpu, size.width, size.height);
                view.gfx.window.request_redraw();
                if view.region.is_none()
                    && self.profile.display.dynamic_resolution
                    && size.width >= 200
                    && size.height >= 200
                {
                    let scale = if self.profile.display.follow_local_scale {
                        (view.gfx.window.scale_factor() * 100.0).round() as u32
                    } else {
                        100
                    };
                    self.pending_layout = Some((Instant::now(), DesktopLayout::single(size.width, size.height, scale)));
                }
            }
            WindowEvent::RedrawRequested => self.redraw(gpu, id),
            WindowEvent::Focused(false) => {
                let ev = self.input.release_all();
                self.send(ev);
            }
            WindowEvent::Focused(true) => {
                // Back from minimise (taskbar, shortcut or our button): re-apply full screen, which
                // the compositor drops on minimise. Sibling monitor windows minimised together via
                // the session bar are brought back too.
                if let Some(v) = self.views.get_mut(&id) {
                    v.minimized = false;
                    if let Some(fs) = v.want_fullscreen.clone() {
                        // Always re-send: winit's cached state can lag the compositor's.
                        v.gfx.window.set_fullscreen(Some(fs));
                    }
                    v.gfx.window.request_redraw();
                }
                // Multi-monitor: restoring one window (taskbar, Alt+Tab) must bring the whole
                // session back. Wayland apps cannot un-minimise themselves, so ask KWin.
                if self.views.len() > 1
                    && self.last_sibling_restore.is_none_or(|t| t.elapsed() > Duration::from_secs(1))
                {
                    self.last_sibling_restore = Some(Instant::now());
                    for v in self.views.values_mut() {
                        v.minimized = false;
                    }
                    crate::kwin::restore_windows(self.title.clone());
                }
                if self.connected() {
                    let locks = bastion_session::keyboard::read_lock_state();
                    self.send(self.input.sync_locks(locks));
                }
            }
            WindowEvent::KeyboardInput { event: k, is_synthetic, .. } => {
                if modal || *is_synthetic || !self.grabbed {
                    return;
                }
                let PhysicalKey::Code(code) = k.physical_key else { return };
                let Some(evdev) = k.physical_key.to_scancode() else {
                    tracing::debug!(?code, "Key without scancode");
                    return;
                };
                match self.input.key(evdev, k.state == ElementState::Pressed, k.repeat) {
                    KeyOutcome::Send(ev) => self.send(ev),
                    KeyOutcome::ReleaseChord(ev) => {
                        self.send(ev);
                        self.grabbed = false;
                        if let Some(v) = self.views.get_mut(&id) {
                            v.bar = BarState::Pinned;
                        }
                        self.request_redraw();
                    }
                    KeyOutcome::Ignore => {}
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                let scale = view.gfx.window.scale_factor();
                let pointer = egui::pos2((position.x / scale) as f32, (position.y / scale) as f32);
                let width = (f64::from(view.gfx.window.inner_size().width) / scale) as f32;
                let fullscreen = view.gfx.window.fullscreen().is_some();
                let (bar, over_bar) = bar_on_pointer(view.bar, pointer, width, fullscreen, view.bar_rect);
                if bar != view.bar {
                    view.bar = bar;
                    if bar == BarState::Hidden {
                        view.bar_rect = None;
                    }
                    view.gfx.window.request_redraw();
                }
                let in_bar = over_bar || view.prompt_rect.is_some_and(|r| r.expand(2.0).contains(pointer));
                let was = view.pointer_in_ui;
                view.pointer_in_ui = in_bar || egui_resp.consumed;
                if was != view.pointer_in_ui {
                    let c = self.remote_cursor.clone();
                    self.apply_cursor(c);
                }
                let Some(view) = self.views.get(&id) else { return };
                if modal || view.pointer_in_ui {
                    return;
                }
                if let Some(rect) = view.image_rect {
                    let src = self.view_src(view);
                    if let Some((x, y)) = map_point(position.x, position.y, rect, src) {
                        let ev = self.input.mouse_move(x, y);
                        self.send(ev);
                    }
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                if modal || view.pointer_in_ui {
                    return;
                }
                if !self.grabbed && *state == ElementState::Pressed {
                    // Clicking back into the session re-captures the keyboard.
                    self.grabbed = true;
                    if !pinned_here {
                        view.bar = BarState::Hidden;
                        view.bar_rect = None;
                    }
                    view.gfx.window.request_redraw();
                }
                let b = match button {
                    winit::event::MouseButton::Left => MouseButton::Left,
                    winit::event::MouseButton::Right => MouseButton::Right,
                    winit::event::MouseButton::Middle => MouseButton::Middle,
                    winit::event::MouseButton::Back => MouseButton::X1,
                    winit::event::MouseButton::Forward => MouseButton::X2,
                    winit::event::MouseButton::Other(_) => return,
                };
                let ev = self.input.mouse_button(b, *state == ElementState::Pressed);
                self.send(ev);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                if modal || view.pointer_in_ui {
                    return;
                }
                let ev = match delta {
                    MouseScrollDelta::LineDelta(x, y) => self.input.wheel_lines(f64::from(*x), f64::from(*y)),
                    MouseScrollDelta::PixelDelta(p) => self.input.wheel_pixels(p.x, p.y),
                };
                self.send(ev);
            }
            _ => {}
        }
    }

    fn view_src(&self, view: &View) -> (f64, f64, f64, f64) {
        match view.region {
            Some((x, y, w, h)) => (f64::from(x), f64::from(y), f64::from(w), f64::from(h)),
            None => {
                let f = self.handle.frame.lock();
                (0.0, 0.0, f64::from(f.width), f64::from(f.height))
            }
        }
    }

    /// Uploads new remote pixels to the GPU (only the dirty region).
    fn upload(&mut self, gpu: &Gpu) {
        let mut f = self.handle.frame.lock();
        self.handle.frame.needs_present.store(false, std::sync::atomic::Ordering::Release);
        if f.width == 0 || f.height == 0 {
            return;
        }
        let recreate = self.texture.as_ref().is_none_or(|(_, _, generation)| *generation != f.generation);
        if recreate {
            // The size is the remote computer's choice; an oversized texture is a wgpu
            // validation error, so end this session instead.
            if let Err(reason) = check_desktop_size(f.width, f.height, gpu.max_texture_side) {
                let (width, height) = (f.width, f.height);
                f.dirty.clear();
                drop(f);
                self.texture = None;
                if self.fatal.is_none() {
                    tracing::error!(
                        width,
                        height,
                        limit = gpu.max_texture_side,
                        "Remote desktop too large for the GPU"
                    );
                }
                self.fail(reason);
                return;
            }
            let tex = gpu.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("remote-desktop"),
                size: wgpu::Extent3d { width: f.width, height: f.height, depth_or_array_layers: 1 },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });
            let view = tex.create_view(&wgpu::TextureViewDescriptor::default());
            for v in self.views.values_mut() {
                match v.tex_id {
                    Some(id) => v.gfx.renderer.update_egui_texture_from_wgpu_texture(
                        &gpu.device,
                        &view,
                        wgpu::FilterMode::Linear,
                        id,
                    ),
                    None => {
                        v.tex_id =
                            Some(v.gfx.renderer.register_native_texture(&gpu.device, &view, wgpu::FilterMode::Linear))
                    }
                }
            }
            self.texture = Some((tex, view, f.generation));
            f.dirty = vec![bastion_session::Rect { x: 0, y: 0, w: f.width, h: f.height }];
        }
        let rects = std::mem::take(&mut f.dirty);
        if rects.is_empty() {
            return;
        }
        if let Some(t) = f.dirty_since.take() {
            bastion_metrics::FRAME_LATENCY.since(t);
        }
        let started = Instant::now();
        let Some((tex, _, _)) = self.texture.as_ref() else { return };
        for d in &rects {
            let offset = (u64::from(d.y) * u64::from(f.width) + u64::from(d.x)) * 4;
            gpu.queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture: tex,
                    mip_level: 0,
                    origin: wgpu::Origin3d { x: d.x, y: d.y, z: 0 },
                    aspect: wgpu::TextureAspect::All,
                },
                &f.data,
                wgpu::TexelCopyBufferLayout { offset, bytes_per_row: Some(f.width * 4), rows_per_image: Some(d.h) },
                wgpu::Extent3d { width: d.w, height: d.h, depth_or_array_layers: 1 },
            );
            bastion_metrics::UI_UPLOAD_BYTES.add(d.area() * 4);
        }
        bastion_metrics::UI_UPLOAD.since(started);
    }

    /// Ends the session from our side with a message for the user (shown on the "Connection
    /// ended" card). Safe to call repeatedly; only the first reason is kept.
    fn fail(&mut self, reason: String) {
        if self.fatal.is_some() {
            return;
        }
        self.handle.send(Command::Disconnect);
        self.fatal = Some(reason.clone());
        self.phase = Phase::Disconnected { reason, error: true };
        self.cert = None;
        self.apply_cursor(RemoteCursor::Default);
        self.request_redraw();
    }

    fn hide_bars(&mut self) {
        let pinned = self.pinned_view();
        for (id, v) in &mut self.views {
            if Some(*id) != pinned {
                v.bar = BarState::Hidden;
                v.bar_rect = None;
            }
        }
    }

    /// The window showing the pinned session bar, if the bar is pinned.
    fn pinned_view(&self) -> Option<WindowId> {
        if !self.pin_bar {
            return None;
        }
        if let Some(id) = self.pin_window.filter(|id| self.views.contains_key(id)) {
            return Some(id);
        }
        // Pinned in an earlier session (or that window is gone): the main monitor's window.
        self.views.iter().min_by_key(|(_, v)| v.region.map_or((0, 0), |(x, y, _, _)| (y, x))).map(|(id, _)| *id)
    }

    /// Keeps the Wayland shortcut inhibitor in sync with grab state.
    fn update_inhibitors(&mut self) {
        let want = self.grab_shortcuts && self.grabbed && self.connected() && self.cert.is_none();
        for v in self.views.values_mut() {
            if want && v.inhibitor.is_none() {
                v.inhibitor = crate::inhibit::ShortcutInhibitor::new(&v.gfx.window);
            }
            if let Some(i) = v.inhibitor.as_mut() {
                i.set(want);
            }
        }
    }

    fn redraw(&mut self, gpu: &Gpu, id: WindowId) {
        self.update_inhibitors();
        self.upload(gpu);
        let (fw, fh) = {
            let f = self.handle.frame.lock();
            (f.width, f.height)
        };
        let phase_text = match &self.phase {
            Phase::Connecting(t) | Phase::Reconnecting(t) => Some(t.clone()),
            _ => None,
        };
        let disconnected = match &self.phase {
            Phase::Disconnected { reason, error } => Some((reason.clone(), *error)),
            _ => None,
        };
        let name = self.profile.display_name().to_owned();
        let quality = self.quality.current.clone();
        let pinned = self.pinned_view() == Some(id);
        let host = self.profile.host.clone();
        let notices: Vec<String> = self.notices.iter().map(|(_, n)| n.clone()).collect();
        let mut cert = self.cert.take();
        let mut actions = Vec::new();
        let grabbed = self.grabbed;
        let offer: Vec<String> = if self.connected() && self.cert.is_none() {
            self.offer.iter().map(|(_, l)| l.clone()).collect()
        } else {
            Vec::new()
        };

        let Some(view) = self.views.get_mut(&id) else { return };
        let src = match view.region {
            Some((x, y, w, h)) => (x, y, w, h),
            None => (0, 0, fw, fh),
        };
        if pinned {
            view.bar = BarState::Pinned;
        }
        let tex_id = view.tex_id;
        let fullscreen = view.gfx.window.fullscreen().is_some();
        let show_bar = view.bar != BarState::Hidden;
        let mut bar_rect = None;
        let mut prompt_rect = None;
        let mut image_rect = None;
        let ppp = view.gfx.window.scale_factor();

        view.gfx.follow_repaints = show_bar
            || phase_text.is_some()
            || disconnected.is_some()
            || cert.is_some()
            || !offer.is_empty()
            || !notices.is_empty()
            || !grabbed;
        let render = bastion_metrics::UI_RENDER.start();
        bastion_metrics::UI_FRAMES.incr();
        view.gfx.frame(gpu, |ui| {
            isolate_keyboard(ui.ctx());
            egui::CentralPanel::no_frame().show(ui, |ui| {
                let avail = ui.max_rect();
                if let (Some(tex), true) = (tex_id, fw > 0 && fh > 0) {
                    // Fit preserving aspect ratio; exact 1:1 when sizes match (dynamic resolution).
                    let (sw, sh) = (src.2 as f32 / ppp as f32, src.3 as f32 / ppp as f32);
                    let scale = (avail.width() / sw).min(avail.height() / sh);
                    let size = egui::vec2(sw * scale, sh * scale);
                    let rect = egui::Rect::from_center_size(avail.center(), size);
                    let uv = egui::Rect::from_min_max(
                        egui::pos2(src.0 as f32 / fw as f32, src.1 as f32 / fh as f32),
                        egui::pos2((src.0 + src.2) as f32 / fw as f32, (src.1 + src.3) as f32 / fh as f32),
                    );
                    ui.painter().rect_filled(avail, 0.0, egui::Color32::BLACK);
                    ui.painter().image(tex, rect, uv, egui::Color32::WHITE);
                    image_rect = Some((
                        f64::from(rect.min.x) * ppp,
                        f64::from(rect.min.y) * ppp,
                        f64::from(rect.width()) * ppp,
                        f64::from(rect.height()) * ppp,
                    ));
                } else {
                    ui.painter().rect_filled(avail, 0.0, egui::Color32::from_rgb(0x10, 0x12, 0x16));
                }

                if show_bar && disconnected.is_none() && phase_text.is_none() {
                    bar_rect =
                        Some(session_bar(ui, &name, quality.as_ref(), grabbed, fullscreen, pinned, &mut actions));
                }
                if !offer.is_empty() {
                    prompt_rect = Some(monitor_prompt(ui, &offer, &mut actions));
                }
                if let Some(text) = &phase_text {
                    status_card(ui, &name, &host, text, &mut actions);
                }
                if let Some((reason, error)) = &disconnected {
                    disconnected_card(ui, &name, reason, *error, &mut actions);
                }
                if let Some((rej, ack, shown)) = cert.as_mut() {
                    let shown_for = shown.get_or_insert_with(Instant::now).elapsed();
                    let armed = cert_armed(shown_for);
                    if !armed {
                        // Repaint when the trust button becomes usable.
                        ui.ctx().request_repaint_after(CERT_ARM_DELAY.saturating_sub(shown_for));
                    }
                    certificate_dialog(ui, rej, ack, armed, &mut actions);
                }
                for (i, n) in notices.iter().enumerate() {
                    toast(ui, i, n);
                }
            });
        });
        drop(render);
        view.image_rect = image_rect;
        view.bar_rect = bar_rect;
        view.prompt_rect = prompt_rect;
        self.cert = cert;
        for a in actions {
            self.action(a, id);
        }
    }

    /// Switches a lone window in or out of full screen in place.
    fn set_single_fullscreen(&mut self, id: WindowId, fs: Option<Fullscreen>) {
        if let Some(v) = self.views.get_mut(&id) {
            v.want_fullscreen = fs.clone();
            v.gfx.window.set_fullscreen(fs);
        }
        // Leaving (or re-entering) full screen frees the window from its monitor.
        self.in_use.clear();
    }

    fn action(&mut self, a: Action, id: WindowId) {
        match a {
            Action::TrustCert(accept) => {
                self.cert = None;
                self.handle.send(Command::CertificateDecision { accept });
            }
            Action::Disconnect => {
                self.handle.send(Command::Disconnect);
                self.want_close = true;
            }
            Action::Close => self.want_close = true,
            Action::Reconnect => self.want_reconnect = true,
            Action::CtrlAltDel => {
                // Ctrl+Alt+Del cannot be typed locally (the local OS takes it); synthesise it.
                for (code, pressed) in [(29, true), (56, true), (111, true), (111, false), (56, false), (29, false)] {
                    if let KeyOutcome::Send(ev) = self.input.key(code, pressed, false) {
                        self.send(ev);
                    }
                }
            }
            Action::ToggleFullscreen => {
                let leaving = self.views.get(&id).is_some_and(|v| v.gfx.window.fullscreen().is_some());
                if leaving {
                    // Remember the arrangement so "Full screen" brings it back.
                    self.restore_fullscreen = Some(self.in_use.clone());
                    if self.views.len() > 1 {
                        // One window per monitor becomes one ordinary window.
                        self.pending_switch = Some(Switch::Windowed);
                    } else {
                        self.set_single_fullscreen(id, None);
                    }
                } else {
                    match self.restore_fullscreen.take().unwrap_or_default() {
                        keys if keys.is_empty() => {
                            self.set_single_fullscreen(id, Some(Fullscreen::Borderless(None)));
                        }
                        // Particular monitor(s): needs new windows placed on them.
                        keys => self.pending_switch = Some(Switch::Fullscreen(keys)),
                    }
                }
            }
            Action::Grab => {
                self.grabbed = true;
                self.hide_bars();
            }
            Action::PinBar(pin) => {
                self.pin_bar = pin;
                self.pin_window = pin.then_some(id);
                self.pin_changed = Some(pin);
                if !pin && let Some(v) = self.views.get_mut(&id) {
                    // Stays until the pointer moves away, like a bar revealed at the top edge.
                    v.bar = BarState::Hover;
                }
            }
            Action::Minimize => {
                // Minimise every window of this session (all monitors) and give the keyboard back.
                let ev = self.input.release_all();
                self.send(ev);
                for v in self.views.values_mut() {
                    v.minimized = true;
                    v.gfx.window.set_minimized(true);
                }
            }
            Action::Refresh => self.handle.send(Command::RefreshScreen),
            Action::UseNewMonitors => self.want_extend = true,
            Action::DismissNewMonitors => self.offer.clear(),
        }
        self.request_redraw();
    }
}

/// UI actions raised by the session overlays.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    TrustCert(bool),
    Disconnect,
    Close,
    Reconnect,
    CtrlAltDel,
    ToggleFullscreen,
    Minimize,
    Grab,
    /// Keep the session bar visible (true) or let it hide again (false).
    PinBar(bool),
    Refresh,
    /// Extend the session onto newly connected monitors.
    UseNewMonitors,
    DismissNewMonitors,
}

fn card_frame() -> egui::Frame {
    egui::Frame::window(&egui::Style::default())
        .fill(egui::Color32::from_rgb(0x1B, 0x1F, 0x26))
        .inner_margin(egui::Margin::same(20))
        .corner_radius(egui::CornerRadius::same(12))
}

fn centered_card(ui: &mut egui::Ui, id: &str, width: f32, add: impl FnOnce(&mut egui::Ui)) {
    egui::Area::new(egui::Id::unique(id))
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            card_frame().show(ui, |ui| {
                ui.set_width(width);
                add(ui);
            });
        });
}

pub fn status_card(ui: &mut egui::Ui, name: &str, host: &str, text: &str, actions: &mut Vec<Action>) {
    centered_card(ui, "status", 380.0, |ui| {
        ui.vertical_centered(|ui| {
            ui.heading(name);
            ui.label(egui::RichText::new(host).color(theme::MUTED));
            ui.add_space(16.0);
            ui.add(egui::Spinner::new().size(28.0).color(theme::ACCENT));
            ui.add_space(10.0);
            ui.label(text);
            ui.add_space(14.0);
            if ui.button("Cancel").clicked() {
                actions.push(Action::Disconnect);
            }
        });
    });
    ui.ctx().request_repaint_after(Duration::from_millis(50));
}

pub fn disconnected_card(ui: &mut egui::Ui, name: &str, reason: &str, error: bool, actions: &mut Vec<Action>) {
    centered_card(ui, "disconnected", 440.0, |ui| {
        ui.vertical_centered(|ui| {
            let (icon, colour) = if error { ("⚠", theme::WARN) } else { ("●", theme::MUTED) };
            ui.label(egui::RichText::new(icon).size(30.0).color(colour));
            ui.heading(if error { "Connection ended" } else { "Disconnected" });
            ui.label(egui::RichText::new(name).color(theme::MUTED));
            ui.add_space(8.0);
            ui.label(reason);
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 210.0).max(0.0) / 2.0);
                if theme::primary_button(ui, "Reconnect").clicked() {
                    actions.push(Action::Reconnect);
                }
                if ui.button("Close").clicked() {
                    actions.push(Action::Close);
                }
            });
        });
    });
}

/// `armed` is false for [`CERT_ARM_DELAY`] after the dialog appears: the trust button is shown
/// but disabled, so input already under way cannot accept the certificate. Cancel always works.
pub fn certificate_dialog(
    ui: &mut egui::Ui,
    rej: &CertificateRejection,
    ack: &mut bool,
    armed: bool,
    actions: &mut Vec<Action>,
) {
    let mismatch = rej.previous_fingerprint.is_some();
    let what = match rej.kind {
        bastion_core::trust::EndpointKind::Gateway => "RD Gateway",
        bastion_core::trust::EndpointKind::Rdp => "remote computer",
    };
    centered_card(ui, "cert", 560.0, |ui| {
        if mismatch {
            ui.label(egui::RichText::new("⚠  The certificate has CHANGED").heading().color(theme::DANGER));
            ui.label(format!(
                "The {what} {} presented a different certificate than the one you trusted before. \
                 This can happen after a legitimate certificate renewal, but it is also exactly what an \
                 attacker intercepting your connection would look like. Verify the new fingerprint with \
                 your administrator before continuing.",
                rej.endpoint
            ));
        } else {
            ui.label(egui::RichText::new("Verify the remote identity").heading());
            ui.label(format!(
                "The {what} {} uses a certificate that isn't issued by an authority this computer trusts \
                 (common for RDP hosts with self-signed certificates). Check the fingerprint below matches \
                 the server's before trusting it.",
                rej.endpoint
            ));
        }
        ui.add_space(8.0);
        egui::Grid::new("certgrid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            let row = |ui: &mut egui::Ui, k: &str, v: &str| {
                ui.label(egui::RichText::new(k).color(theme::MUTED));
                ui.add(egui::Label::new(v).wrap());
                ui.end_row();
            };
            row(ui, "Subject", &rej.subject);
            row(ui, "Issuer", &rej.issuer);
            row(ui, "Expires", &rej.not_after);
            row(ui, "Problem", &rej.reason);
        });
        ui.add_space(6.0);
        ui.label(egui::RichText::new("SHA-256 fingerprint").color(theme::MUTED));
        ui.add(egui::Label::new(egui::RichText::new(&rej.fingerprint).monospace()).wrap());
        if let Some(prev) = &rej.previous_fingerprint {
            ui.label(egui::RichText::new("Previously trusted").color(theme::MUTED));
            ui.add(egui::Label::new(egui::RichText::new(prev).monospace().color(theme::MUTED)).wrap());
            ui.checkbox(ack, "I have verified the new certificate and want to replace the old one");
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let enabled = armed && (!mismatch || *ack);
            let label = if mismatch { "Replace and connect" } else { "Trust and connect" };
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(egui::RichText::new(label).strong()).fill(if mismatch {
                        theme::DANGER
                    } else {
                        theme::ACCENT
                    }),
                )
                .clicked()
            {
                actions.push(Action::TrustCert(true));
            }
            if ui.button("Cancel").clicked() {
                actions.push(Action::TrustCert(false));
            }
        });
    });
}

/// Draws the session bar and returns where it was drawn (points).
pub fn session_bar(
    ui: &mut egui::Ui,
    name: &str,
    quality: Option<&crate::quality::Quality>,
    grabbed: bool,
    fullscreen: bool,
    pinned: bool,
    actions: &mut Vec<Action>,
) -> egui::Rect {
    egui::Area::new(egui::Id::unique("session-bar"))
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 4.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::window(ui.style())
                .inner_margin(egui::Margin::symmetric(10, 4))
                .corner_radius(egui::CornerRadius::same(8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(name).strong());
                        quality_chip(ui, quality);
                        ui.separator();
                        if !grabbed {
                            ui.label(egui::RichText::new("Keyboard released").color(theme::WARN));
                            if ui.button("Capture keyboard").clicked() {
                                actions.push(Action::Grab);
                            }
                        }
                        if ui.button("Ctrl+Alt+Del").on_hover_text("Send Ctrl+Alt+Del to the remote computer").clicked()
                        {
                            actions.push(Action::CtrlAltDel);
                        }
                        if ui.button("Refresh").on_hover_text("Ask the remote computer to redraw the screen").clicked()
                        {
                            actions.push(Action::Refresh);
                        }
                        if ui.button("Minimise").on_hover_text("Minimise the remote session").clicked() {
                            actions.push(Action::Minimize);
                        }
                        if ui.button(if fullscreen { "Exit full screen" } else { "Full screen" }).clicked() {
                            actions.push(Action::ToggleFullscreen);
                        }
                        if theme::danger_button(ui, "Disconnect").clicked() {
                            actions.push(Action::Disconnect);
                        }
                        ui.separator();
                        let (pin_label, pin_hint) = if pinned {
                            ("Unpin", "Let the bar hide again (move the pointer to the top edge to show it)")
                        } else {
                            ("Pin", "Keep this bar visible")
                        };
                        if ui.selectable_label(pinned, pin_label).on_hover_text(pin_hint).clicked() {
                            actions.push(Action::PinBar(!pinned));
                        }
                    });
                });
        })
        .response
        .rect
}

/// Coloured dot plus latency; hovering shows the details.
fn quality_chip(ui: &mut egui::Ui, quality: Option<&crate::quality::Quality>) {
    use crate::quality::{Level, format_ms};
    let level = quality.map_or(Level::Unknown, |q| q.level);
    let color = match level {
        Level::Good => theme::OK,
        Level::Fair => theme::WARN,
        Level::Poor => theme::DANGER,
        Level::Unknown => theme::MUTED,
    };
    let text = quality.map_or_else(|| "— ms".to_owned(), |q| q.chip_text());
    let inner = ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        let (dot, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter().circle_filled(dot.center(), 4.5, color);
        ui.label(egui::RichText::new(text).color(theme::MUTED));
    });
    let response = ui.interact(inner.response.rect, ui.scope_id().with("connection-quality"), egui::Sense::hover());
    response.on_hover_ui(|ui| {
        ui.label(egui::RichText::new(format!("Connection: {}", level.label())).strong().color(color));
        let Some(q) = quality else {
            ui.label("Measuring the connection…");
            return;
        };
        egui::Grid::new("connection-quality-grid").num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(egui::RichText::new(k).color(theme::MUTED));
                ui.label(v);
                ui.end_row();
            };
            match (q.latency_ms, q.latency_source) {
                (Some(ms), Some(src)) => {
                    let jitter = q.jitter_ms.map(|j| format!(" (± {} ms)", format_ms(j))).unwrap_or_default();
                    row("Latency", format!("{} ms{jitter}", format_ms(ms)));
                    row("", src.describe().to_owned());
                }
                _ => row("Latency", "not available".into()),
            }
            if let Some(l) = q.loss_pct {
                row("Packet loss", format!("{l:.1} %"));
            }
            row("Frame rate", format!("{:.0} fps", q.fps));
            row("Download", format!("{:.1} Mbit/s", q.down_mbps));
            row("Upload", format!("{:.2} Mbit/s", q.up_mbps));
            if let Some(c) = q.capacity_mbps {
                row("Available", format!("{c:.0} Mbit/s (remote computer's estimate)"));
            }
            row("Route", if q.via_gateway { "Through RD Gateway" } else { "Direct" }.into());
            row("Transport", if q.udp { "UDP (graphics and audio)" } else { "TCP" }.into());
        });
    });
}

/// Asks whether to extend the session onto newly connected monitors; returns where it was drawn
/// (points) so only the prompt itself captures the pointer.
pub fn monitor_prompt(ui: &mut egui::Ui, labels: &[String], actions: &mut Vec<Action>) -> egui::Rect {
    egui::Area::new(egui::Id::unique("monitor-prompt"))
        .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -48.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            card_frame().inner_margin(egui::Margin::symmetric(18, 14)).show(ui, |ui| {
                ui.set_max_width(460.0);
                let (title, question) = if labels.len() == 1 {
                    ("New monitor connected", "Extend this session onto it?")
                } else {
                    ("New monitors connected", "Extend this session onto them?")
                };
                ui.label(egui::RichText::new(title).strong());
                for l in labels {
                    ui.label(egui::RichText::new(l).color(theme::MUTED));
                }
                ui.label(question);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if theme::primary_button(ui, "Use multiple monitors").clicked() {
                        actions.push(Action::UseNewMonitors);
                    }
                    if ui.button("Not now").clicked() {
                        actions.push(Action::DismissNewMonitors);
                    }
                });
            });
        })
        .response
        .rect
}

fn toast(ui: &mut egui::Ui, idx: usize, text: &str) {
    egui::Area::new(egui::Id::unique(("toast", idx)))
        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0 - idx as f32 * 52.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            card_frame().inner_margin(egui::Margin::symmetric(14, 10)).show(ui, |ui| {
                ui.set_max_width(360.0);
                ui.label(egui::RichText::new(text).color(theme::WARN));
            });
        });
}

#[cfg(test)]
mod bar_tests {
    use super::*;

    const W: f32 = 2327.0; // the user's 4K monitor at 165 %, in points
    fn bar() -> Option<egui::Rect> {
        Some(egui::Rect::from_min_max(egui::pos2(W / 2.0 - 280.0, 4.0), egui::pos2(W / 2.0 + 280.0, 40.0)))
    }

    #[test]
    fn keyboard_and_ime_events_never_reach_egui() {
        use winit::event::{DeviceId, Ime};
        assert!(!egui_may_see(&WindowEvent::Ime(Ime::Enabled)));
        assert!(!egui_may_see(&WindowEvent::Ime(Ime::Commit("\t\t\n".into()))));
        // Pointer, focus and redraw events still drive the overlays.
        let position = winit::dpi::PhysicalPosition::new(10.0, 10.0);
        assert!(egui_may_see(&WindowEvent::CursorMoved { device_id: DeviceId::dummy(), position }));
        assert!(egui_may_see(&WindowEvent::MouseInput {
            device_id: DeviceId::dummy(),
            state: ElementState::Pressed,
            button: winit::event::MouseButton::Left,
        }));
        assert!(egui_may_see(&WindowEvent::Focused(true)));
        assert!(egui_may_see(&WindowEvent::RedrawRequested));
    }

    #[test]
    fn trust_button_arms_only_after_the_delay() {
        assert!(!cert_armed(Duration::ZERO));
        assert!(!cert_armed(CERT_ARM_DELAY - Duration::from_millis(1)));
        assert!(cert_armed(CERT_ARM_DELAY));
        assert!(CERT_ARM_DELAY >= Duration::from_secs(1), "long enough to notice the dialog");
    }

    #[test]
    fn oversized_desktop_is_refused_with_a_friendly_message() {
        assert_eq!(check_desktop_size(3840, 2160, 16384), Ok(()));
        assert_eq!(check_desktop_size(16384, 16384, 16384), Ok(()));
        // ResetGraphics 32766×8 / Demand Active 40000×8 on a 16384-limit adapter.
        for (w, h) in [(32766, 8), (40000, 8), (8, 32766), (16385, 16385)] {
            let msg = check_desktop_size(w, h, 16384).unwrap_err();
            assert!(msg.contains(&w.to_string()) && msg.contains("16384"), "{msg}");
            assert!(!msg.contains(".rs") && !msg.contains("wgpu") && !msg.contains('/'), "{msg}");
        }
    }

    #[test]
    fn a_redraw_never_schedules_another() {
        // egui-winit reports repaint=true for RedrawRequested; following it looped forever.
        assert!(is_redraw_echo(&WindowEvent::RedrawRequested));
        assert!(!is_redraw_echo(&WindowEvent::Occluded(false)));
        assert!(!is_redraw_echo(&WindowEvent::Focused(true)));
    }

    #[test]
    fn top_right_corner_never_reveals_the_bar() {
        // Reaching for a remote browser's close button.
        let (s, over) = bar_on_pointer(BarState::Hidden, egui::pos2(W - 10.0, 0.0), W, true, None);
        assert_eq!((s, over), (BarState::Hidden, false));
        let (s, _) = bar_on_pointer(BarState::Hidden, egui::pos2(15.0, 0.0), W, true, None);
        assert_eq!(s, BarState::Hidden);
    }

    #[test]
    fn top_centre_reveals_only_in_full_screen() {
        assert_eq!(bar_on_pointer(BarState::Hidden, egui::pos2(W / 2.0, 0.0), W, true, None).0, BarState::Hover);
        assert_eq!(bar_on_pointer(BarState::Hidden, egui::pos2(W / 2.0, 0.0), W, false, None).0, BarState::Hidden);
    }

    #[test]
    fn only_the_bar_itself_captures_the_pointer() {
        // Bar visible, pointer at the top edge but far right: input goes to the remote PC.
        let (_, over) = bar_on_pointer(BarState::Hover, egui::pos2(W - 10.0, 2.0), W, true, bar());
        assert!(!over);
        let (_, over) = bar_on_pointer(BarState::Hover, egui::pos2(W / 2.0, 20.0), W, true, bar());
        assert!(over);
    }

    #[test]
    fn hover_bar_hides_when_pointer_leaves_but_pinned_stays() {
        let away = egui::pos2(W / 2.0, 300.0);
        assert_eq!(bar_on_pointer(BarState::Hover, away, W, true, bar()).0, BarState::Hidden);
        assert_eq!(bar_on_pointer(BarState::Pinned, away, W, true, bar()).0, BarState::Pinned);
        // Moving along the bar itself keeps it.
        assert_eq!(
            bar_on_pointer(BarState::Hover, egui::pos2(W / 2.0 + 200.0, 30.0), W, true, bar()).0,
            BarState::Hover
        );
    }
}
