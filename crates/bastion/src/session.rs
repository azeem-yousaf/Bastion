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
    cert: Option<(Box<CertificateRejection>, bool)>,
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
    /// Set when sign-in failed, so a remembered (wrong) password is discarded.
    pub auth_failed: bool,
}

#[derive(Clone)]
enum RemoteCursor {
    Default,
    Hidden,
    Custom(CustomCursor),
}

const RESIZE_DEBOUNCE: Duration = Duration::from_millis(300);
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
        params_without_layout: impl FnOnce(DesktopLayout) -> bastion_session::ConnectParams,
        waker: bastion_session::Waker,
        grab_shortcuts: bool,
    ) -> anyhow::Result<Self> {
        let title = format!("{} — Bastion", profile.display_name());
        let session_title = title.clone();
        let mut views = HashMap::new();
        let layout = match profile.display.mode {
            DisplayMode::AllMonitors => {
                let monitors: Vec<_> = event_loop.available_monitors().collect();
                // Create one fullscreen window per monitor first: the window knows the true
                // fractional scale (e.g. 165%), the monitor handle only the rounded one.
                let mut windows = Vec::new();
                for m in &monitors {
                    let attrs = Window::default_attributes()
                        .with_title(title.clone())
                        .with_name("bastion", "bastion")
                        .with_fullscreen(Some(Fullscreen::Borderless(Some(m.clone()))));
                    windows.push(Arc::new(event_loop.create_window(attrs)?));
                }
                let locals: Vec<_> = monitors
                    .iter()
                    .map(|m| {
                        // winit reports logical position x integer output scale; undo that.
                        let s = m.scale_factor().max(1.0);
                        let pos = m.position();
                        bastion_session::LocalMonitor {
                            logical_x: (f64::from(pos.x) / s).round() as i32,
                            logical_y: (f64::from(pos.y) / s).round() as i32,
                            width: m.size().width,
                            height: m.size().height,
                            scale: s,
                        }
                    })
                    .collect();
                let mut layout = bastion_session::pack_monitors(&locals, profile.display.follow_local_scale);
                if profile.display.follow_local_scale {
                    for (spec, w) in layout.monitors.iter_mut().zip(&windows) {
                        spec.scale = (w.scale_factor() * 100.0).round() as u32;
                    }
                    layout = layout.normalized();
                }
                tracing::info!(?layout, "Multi-monitor layout");
                let (bx, by, _, _) = layout.bounds();
                for ((window, spec), monitor) in windows.into_iter().zip(&layout.monitors).zip(&monitors) {
                    let region = ((spec.x - bx) as u32, (spec.y - by) as u32, spec.width, spec.height);
                    let gfx = WindowGfx::new(gpu, window.clone(), None)?;
                    views.insert(
                        window.id(),
                        View {
                            inhibitor: None,
                            gfx,
                            region: Some(region),
                            tex_id: None,
                            image_rect: None,
                            pointer_in_ui: false,
                            bar: BarState::Hidden,
                            bar_rect: None,
                            want_fullscreen: Some(Fullscreen::Borderless(Some(monitor.clone()))),
                            minimized: false,
                        },
                    );
                }
                layout
            }
            mode => {
                let mut attrs = Window::default_attributes()
                    .with_title(title)
                    .with_name("bastion", "bastion")
                    .with_inner_size(winit::dpi::LogicalSize::new(profile.display.width, profile.display.height))
                    .with_min_inner_size(winit::dpi::LogicalSize::new(320, 240));
                if mode == DisplayMode::Fullscreen {
                    attrs = attrs.with_fullscreen(Some(Fullscreen::Borderless(None)));
                }
                let window = Arc::new(event_loop.create_window(attrs)?);
                let size = window.inner_size();
                let scale = if profile.display.follow_local_scale {
                    (window.scale_factor() * 100.0).round() as u32
                } else {
                    100
                };
                let gfx = WindowGfx::new(gpu, window.clone(), None)?;
                views.insert(
                    window.id(),
                    View {
                        inhibitor: None,
                        gfx,
                        region: None,
                        tex_id: None,
                        image_rect: None,
                        pointer_in_ui: false,
                        bar: BarState::Hidden,
                        bar_rect: None,
                        want_fullscreen: (mode == DisplayMode::Fullscreen).then_some(Fullscreen::Borderless(None)),
                        minimized: false,
                    },
                );
                DesktopLayout::single(size.width.max(640), size.height.max(480), scale)
            }
        };
        let handle = SessionHandle::spawn(params_without_layout(layout), waker);
        Ok(Self {
            profile,
            handle,
            views,
            phase: Phase::Connecting("Starting…".into()),
            cert: None,
            notices: Vec::new(),
            input: InputState::new(),
            grabbed: true,
            texture: None,
            cursor_cache: HashMap::new(),
            remote_cursor: RemoteCursor::Default,
            pending_layout: None,
            want_close: false,
            want_reconnect: false,
            auth_failed: false,
            grab_shortcuts,
            title: session_title,
            last_sibling_restore: None,
        })
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
                Event::Status(s) => {
                    self.phase = match s {
                        Status::ConnectingGateway => Phase::Connecting("Connecting to RD Gateway…".into()),
                        Status::Connecting => Phase::Connecting("Connecting to remote computer…".into()),
                        Status::Authenticating => Phase::Connecting("Signing in…".into()),
                        Status::Connected { .. } => Phase::Connected,
                        Status::Reconnecting { attempt, max } => {
                            Phase::Reconnecting(format!("Connection lost. Reconnecting (attempt {attempt} of {max})…"))
                        }
                    };
                    if self.connected() {
                        let locks = bastion_session::keyboard::read_lock_state();
                        self.send(self.input.sync_locks(locks));
                    }
                }
                Event::Pointer(p) => self.set_remote_cursor(event_loop, p),
                Event::CertificatePrompt(r) => self.cert = Some((r, false)),
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
                    self.phase = Phase::Disconnected { reason, error };
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
        self.notices.retain(|(t, _)| t.elapsed() < Duration::from_secs(8));
        if changed {
            self.request_redraw();
        }
        changed
    }

    pub fn next_deadline(&mut self) -> Option<Instant> {
        let mut d = self.pending_layout.as_ref().map(|(t, _)| *t + RESIZE_DEBOUNCE);
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
        let Some(view) = self.views.get_mut(&id) else { return };
        let egui_resp = view.gfx.egui.on_window_event(&view.gfx.window, event);
        if egui_resp.repaint {
            view.gfx.window.request_redraw();
        }
        let modal = self.cert.is_some() || !matches!(self.phase, Phase::Connected);

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
                if modal || *is_synthetic || !self.grabbed || egui_resp.consumed {
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
                let in_bar = over_bar;
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
                    view.bar = BarState::Hidden;
                    view.bar_rect = None;
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
            f.dirty = Some(bastion_session::Rect { x: 0, y: 0, w: f.width, h: f.height });
        }
        let Some(d) = f.dirty.take() else { return };
        let (tex, _, _) = self.texture.as_ref().expect("texture exists");
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
    }

    fn hide_bars(&mut self) {
        for v in self.views.values_mut() {
            v.bar = BarState::Hidden;
            v.bar_rect = None;
        }
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
        let host = self.profile.host.clone();
        let notices: Vec<String> = self.notices.iter().map(|(_, n)| n.clone()).collect();
        let mut cert = self.cert.take();
        let mut actions = Vec::new();
        let grabbed = self.grabbed;

        let Some(view) = self.views.get_mut(&id) else { return };
        let src = match view.region {
            Some((x, y, w, h)) => (x, y, w, h),
            None => (0, 0, fw, fh),
        };
        let tex_id = view.tex_id;
        let fullscreen = view.gfx.window.fullscreen().is_some();
        let show_bar = view.bar != BarState::Hidden;
        let mut bar_rect = None;
        let mut image_rect = None;
        let ppp = view.gfx.window.scale_factor();

        view.gfx.frame(gpu, |ui| {
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
                    bar_rect = Some(session_bar(ui, &name, grabbed, fullscreen, &mut actions));
                }
                if let Some(text) = &phase_text {
                    status_card(ui, &name, &host, text, &mut actions);
                }
                if let Some((reason, error)) = &disconnected {
                    disconnected_card(ui, &name, reason, *error, &mut actions);
                }
                if let Some((rej, ack)) = cert.as_mut() {
                    certificate_dialog(ui, rej, ack, &mut actions);
                }
                for (i, n) in notices.iter().enumerate() {
                    toast(ui, i, n);
                }
            });
        });
        view.image_rect = image_rect;
        view.bar_rect = bar_rect;
        self.cert = cert;
        for a in actions {
            self.action(a, id);
        }
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
                if let Some(v) = self.views.get_mut(&id) {
                    let fs =
                        if v.gfx.window.fullscreen().is_some() { None } else { Some(Fullscreen::Borderless(None)) };
                    v.want_fullscreen = fs.clone();
                    v.gfx.window.set_fullscreen(fs);
                }
            }
            Action::Grab => {
                self.grabbed = true;
                self.hide_bars();
            }
            Action::HideBar => self.hide_bars(),
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
    HideBar,
    Refresh,
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

pub fn certificate_dialog(ui: &mut egui::Ui, rej: &CertificateRejection, ack: &mut bool, actions: &mut Vec<Action>) {
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
            let enabled = !mismatch || *ack;
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
    grabbed: bool,
    fullscreen: bool,
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
                        if ui.small_button("×").on_hover_text("Hide").clicked() {
                            actions.push(Action::HideBar);
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
