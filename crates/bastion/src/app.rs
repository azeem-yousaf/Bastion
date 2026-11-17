//! Window/event-loop orchestration: the manager window plus any number of session windows.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_core::AppPaths;
use bastion_core::trust::TrustStore;
use bastion_session::ConnectParams;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoopProxy};
use winit::platform::startup_notify::WindowAttributesExtStartupNotify as _;
use winit::platform::wayland::WindowAttributesExtWayland as _;
use winit::window::{ActivationToken, Window, WindowId};

use crate::gpu::{Gpu, WindowGfx};
use crate::manager::{ConnectRequest, Manager};
use crate::monitors::{self, Screen};
use crate::session::Session;

#[derive(Debug, Clone, Copy)]
pub enum UserEvent {
    /// Something in a session changed (pixels, status…).
    Wake,
    /// The connection manager has news (device list, file picker…).
    ManagerWake,
    TrayOpen,
    TrayQuit,
    /// Bastion was launched again while running: requests wait in `App::launches`.
    Launched,
}

struct Live {
    session: Session,
    request: ConnectRequest,
}

pub struct App {
    trust: Arc<Mutex<TrustStore>>,
    proxy: EventLoopProxy<UserEvent>,
    gpu: Option<Gpu>,
    manager: Manager,
    manager_win: Option<WindowGfx>,
    sessions: Vec<Live>,
    startup_import: Option<PathBuf>,
    /// Requests from later launches, forwarded by the single-instance listener.
    launches: Option<std::sync::mpsc::Receiver<crate::single::Request>>,
    keyboard_layout: u32,
    client_name: String,
    tray: Option<crate::tray::TrayHandle>,
    tray_sessions: usize,
    /// Connected monitors as last acted on.
    screens: Vec<Screen>,
    /// A monitor change waiting to settle: (first seen, keys). Hot-plugging often produces a
    /// burst of output changes (and KDE re-arranges screens), so act once it is stable.
    monitor_change: Option<(Instant, Vec<String>)>,
}

const MONITOR_SETTLE: Duration = Duration::from_millis(1500);

impl App {
    pub fn new(
        paths: AppPaths,
        proxy: EventLoopProxy<UserEvent>,
        startup_import: Option<PathBuf>,
        launches: Option<std::sync::mpsc::Receiver<crate::single::Request>>,
    ) -> anyhow::Result<Self> {
        let trust = Arc::new(Mutex::new(TrustStore::load(&paths)?));
        let p = proxy.clone();
        let manager = Manager::new(
            paths.clone(),
            trust.clone(),
            Arc::new(move || {
                let _ = p.send_event(UserEvent::ManagerWake);
            }),
        )?;
        let tray = crate::tray::start(proxy.clone());
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        Ok(Self {
            trust,
            proxy,
            gpu: None,
            manager,
            manager_win: None,
            sessions: Vec::new(),
            startup_import,
            launches,
            keyboard_layout: bastion_session::keyboard::detect_klid(),
            tray,
            tray_sessions: 0,
            screens: Vec::new(),
            monitor_change: None,
            client_name: host.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(15).collect(),
        })
    }

    fn waker(&self) -> bastion_session::Waker {
        let p = self.proxy.clone();
        Arc::new(move || {
            let _ = p.send_event(UserEvent::Wake);
        })
    }

    fn open_manager(&mut self, event_loop: &ActiveEventLoop, token: Option<ActivationToken>) -> anyhow::Result<()> {
        let mut attrs = Window::default_attributes()
            .with_title("Bastion")
            .with_inner_size(winit::dpi::LogicalSize::new(980, 640))
            .with_min_inner_size(winit::dpi::LogicalSize::new(720, 480))
            .with_name("bastion", "bastion");
        if let Some(token) = token {
            attrs = attrs.with_activation_token(token);
        }
        let window = Arc::new(event_loop.create_window(attrs)?);
        let gfx = match &self.gpu {
            Some(gpu) => WindowGfx::new(gpu, window, None)?,
            None => {
                let (gpu, surface) = Gpu::new(event_loop.owned_display_handle(), window.clone())?;
                let gfx = WindowGfx::new(&gpu, window, Some(surface))?;
                self.gpu = Some(gpu);
                gfx
            }
        };
        self.manager_win = Some(gfx);
        Ok(())
    }

    /// Bastion was launched again (application icon, or a `.rdp` file opened) while this
    /// instance was running: bring the main window up and import the file, if any.
    fn handle_launches(&mut self, event_loop: &ActiveEventLoop) {
        let requests: Vec<_> = self.launches.as_ref().map(|rx| rx.try_iter().collect()).unwrap_or_default();
        for request in requests {
            tracing::info!(import = request.import.is_some(), "Launched again; showing the main window");
            // Wayland does not let an application raise a window it already has, so a visible
            // (or minimised) window is replaced by a new one carrying the launcher's activation
            // token. The manager's state lives outside the window and is kept.
            if request.token.is_some() || self.manager_win.is_none() {
                self.manager_win = None;
                if let Err(e) = self.open_manager(event_loop, request.token.map(ActivationToken::from_raw)) {
                    tracing::error!(error = %e, "Cannot reopen main window");
                }
            } else if let Some(w) = &self.manager_win {
                w.window.set_minimized(false);
                w.window.focus_window();
            }
            if let Some(path) = request.import {
                self.manager.import_file(&path);
            }
            if let Some(w) = &self.manager_win {
                w.window.request_redraw();
            }
        }
    }

    fn start_session(&mut self, event_loop: &ActiveEventLoop, request: ConnectRequest) {
        let Some(gpu) = &self.gpu else { return };
        let trust = self.trust.clone();
        let (kl, cn) = (self.keyboard_layout, self.client_name.clone());
        let (profile, password, gw) =
            (request.profile.clone(), request.password.clone(), request.gateway_password.clone());
        let result = Session::open(
            event_loop,
            gpu,
            request.profile.clone(),
            &self.screens,
            move |layout| ConnectParams {
                profile,
                password,
                gateway_password: gw,
                layout,
                trust,
                keyboard_layout: kl,
                client_name: cn,
                audio_host: None,
                camera_host: None,
            },
            self.waker(),
            &self.manager.settings,
        );
        match result {
            Ok(session) => self.sessions.push(Live { session, request }),
            Err(e) => tracing::error!(error = %e, "Could not open session window"),
        }
    }

    /// Detects monitors being plugged in or out; returns when to check again while a change is
    /// settling.
    fn watch_monitors(&mut self, event_loop: &ActiveEventLoop) -> Option<Instant> {
        let now = monitors::snapshot(event_loop);
        let keys = monitors::keys(&now);
        if keys == monitors::keys(&self.screens) {
            self.monitor_change = None;
            if now != self.screens {
                // Same monitors, new geometry/modes: just refresh the handles and labels.
                self.screens = now;
                self.manager.set_monitors(&self.screens);
            }
            return None;
        }
        match &self.monitor_change {
            Some((at, pending)) if *pending == keys => {
                if at.elapsed() < MONITOR_SETTLE {
                    return Some(*at + MONITOR_SETTLE);
                }
            }
            _ => {
                self.monitor_change = Some((Instant::now(), keys));
                return Some(Instant::now() + MONITOR_SETTLE);
            }
        }
        self.monitor_change = None;
        let before = monitors::keys(&self.screens);
        tracing::info!(?before, now = ?keys, "Local monitors changed");
        self.screens = now;
        self.manager.set_monitors(&self.screens);
        for live in &mut self.sessions {
            live.session.monitors_changed(&before, &self.screens);
        }
        None
    }

    fn reap_sessions(&mut self, event_loop: &ActiveEventLoop) {
        let mut reconnect = Vec::new();
        let mut pin = None;
        self.sessions.retain_mut(|live| {
            if let Some(p) = live.session.pin_changed.take() {
                pin = Some(p);
            }
            if live.session.auth_failed {
                live.session.auth_failed = false;
                self.manager.forget_password_after_auth_failure(live.request.profile.id);
            }
            if live.session.want_reconnect {
                reconnect.push(ConnectRequest {
                    profile: live.request.profile.clone(),
                    password: live.request.password.clone(),
                    gateway_password: live.request.gateway_password.clone(),
                });
                return false;
            }
            !live.session.want_close
        });
        if let Some(p) = pin {
            self.manager.set_pin_session_bar(p);
        }
        for r in reconnect {
            self.start_session(event_loop, r);
        }
        if self.sessions.is_empty() && self.manager_win.is_none() && self.tray.is_none() {
            event_loop.exit();
        }
        if let Some(t) = &self.tray
            && self.tray_sessions != self.sessions.len()
        {
            self.tray_sessions = self.sessions.len();
            crate::tray::set_sessions(t, self.tray_sessions);
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.manager_win.is_none() && self.gpu.is_none() {
            if let Err(e) = self.open_manager(event_loop, None) {
                tracing::error!(error = %e, "Cannot open main window");
                event_loop.exit();
                return;
            }
            self.screens = monitors::snapshot(event_loop);
            self.manager.set_monitors(&self.screens);
            tracing::info!(monitors = ?monitors::keys(&self.screens), "Local monitors");
            if let Some(path) = self.startup_import.take() {
                self.manager.import_file(&path);
            }
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::TrayQuit => {
                tracing::info!("Quit requested from the system tray");
                self.sessions.clear();
                event_loop.exit();
                return;
            }
            UserEvent::TrayOpen => match &self.manager_win {
                Some(w) => {
                    w.window.set_minimized(false);
                    w.window.focus_window();
                }
                None => {
                    if let Err(e) = self.open_manager(event_loop, None) {
                        tracing::error!(error = %e, "Cannot reopen main window");
                    }
                }
            },
            UserEvent::ManagerWake => {
                if let Some(w) = &self.manager_win {
                    w.window.request_redraw();
                }
            }
            UserEvent::Launched => self.handle_launches(event_loop),
            UserEvent::Wake => {}
        }
        for live in &mut self.sessions {
            live.session.poll(event_loop);
            if live.session.handle.frame.needs_present.load(std::sync::atomic::Ordering::Acquire) {
                bastion_metrics::UI_REDRAW_PIXELS.incr();
                live.session.request_redraw();
            }
        }
        // The manager is not redrawn for session wake-ups (every remote frame): it has its own.
        self.reap_sessions(event_loop);
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        let Some(gpu) = self.gpu.as_ref() else { return };

        if self.manager_win.as_ref().is_some_and(|w| w.window.id() == id) {
            let win = self.manager_win.as_mut().expect("checked");
            let resp = win.egui.on_window_event(&win.window, &event);
            if resp.repaint && !crate::session::is_redraw_echo(&event) {
                win.window.request_redraw();
            }
            match event {
                WindowEvent::CloseRequested => {
                    // With a tray icon, closing only hides the window; Bastion keeps running.
                    self.manager_win = None;
                    if self.sessions.is_empty() && self.tray.is_none() {
                        event_loop.exit();
                    }
                }
                WindowEvent::Resized(s) => win.resize(gpu, s.width, s.height),
                WindowEvent::RedrawRequested => {
                    let manager = &mut self.manager;
                    let mut request = None;
                    win.frame(gpu, |ui| {
                        if let Some(r) = manager.ui(ui) {
                            request = Some(r);
                        }
                    });
                    if let Some(r) = request {
                        self.start_session(event_loop, r);
                    }
                }
                _ => {}
            }
            return;
        }

        if let Some(live) = self.sessions.iter_mut().find(|l| l.session.owns(id)) {
            // Redraws are measured as ui.render; this is input/resize/focus handling.
            let started = (!matches!(event, WindowEvent::RedrawRequested)).then(Instant::now);
            live.session.window_event(gpu, id, &event);
            if let Some(t) = started {
                bastion_metrics::UI_EVENT.since(t);
            }
        }
        self.reap_sessions(event_loop);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let mut deadline: Option<Instant> = self.watch_monitors(event_loop);
        for live in &mut self.sessions {
            live.session.poll(event_loop);
            if let Some(gpu) = self.gpu.as_ref() {
                live.session.apply_monitor_changes(event_loop, gpu, &self.screens);
            }
            if let Some(d) = live.session.next_deadline() {
                deadline = Some(deadline.map_or(d, |x| x.min(d)));
            }
        }
        if let Some(t) = self.manager_win.as_mut().and_then(|w| w.tick()) {
            deadline = Some(deadline.map_or(t, |x| x.min(t)));
        }
        self.reap_sessions(event_loop);
        event_loop.set_control_flow(match deadline {
            Some(d) => ControlFlow::WaitUntil(d),
            None => ControlFlow::Wait,
        });
    }
}
