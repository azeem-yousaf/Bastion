//! Window/event-loop orchestration: the manager window plus any number of session windows.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bastion_core::AppPaths;
use bastion_core::trust::TrustStore;
use bastion_session::ConnectParams;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoopProxy};
use winit::platform::wayland::WindowAttributesExtWayland as _;
use winit::window::{Window, WindowId};

use crate::gpu::{Gpu, WindowGfx};
use crate::manager::{ConnectRequest, Manager};
use crate::session::Session;

#[derive(Debug, Clone, Copy)]
pub enum UserEvent {
    Wake,
    TrayOpen,
    TrayQuit,
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
    keyboard_layout: u32,
    client_name: String,
    tray: Option<crate::tray::TrayHandle>,
    tray_sessions: usize,
}

impl App {
    pub fn new(
        paths: AppPaths,
        proxy: EventLoopProxy<UserEvent>,
        startup_import: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let trust = Arc::new(Mutex::new(TrustStore::load(&paths)?));
        let p = proxy.clone();
        let manager = Manager::new(
            paths.clone(),
            trust.clone(),
            Arc::new(move || {
                let _ = p.send_event(UserEvent::Wake);
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
            keyboard_layout: bastion_session::keyboard::detect_klid(),
            tray,
            tray_sessions: 0,
            client_name: host.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(15).collect(),
        })
    }

    fn waker(&self) -> bastion_session::Waker {
        let p = self.proxy.clone();
        Arc::new(move || {
            let _ = p.send_event(UserEvent::Wake);
        })
    }

    fn open_manager(&mut self, event_loop: &ActiveEventLoop) -> anyhow::Result<()> {
        let attrs = Window::default_attributes()
            .with_title("Bastion")
            .with_inner_size(winit::dpi::LogicalSize::new(980, 640))
            .with_min_inner_size(winit::dpi::LogicalSize::new(720, 480))
            .with_name("bastion", "bastion");
        let window = Arc::new(event_loop.create_window(attrs)?);
        let gfx = match &self.gpu {
            Some(gpu) => WindowGfx::new(gpu, window, None)?,
            None => {
                let (gpu, surface) = Gpu::new(window.clone())?;
                let gfx = WindowGfx::new(&gpu, window, Some(surface))?;
                self.gpu = Some(gpu);
                gfx
            }
        };
        self.manager_win = Some(gfx);
        Ok(())
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
            move |layout| ConnectParams {
                profile,
                password,
                gateway_password: gw,
                layout,
                trust,
                keyboard_layout: kl,
                client_name: cn,
                audio_host: None,
            },
            self.waker(),
            self.manager.settings.grab_system_shortcuts,
        );
        match result {
            Ok(session) => self.sessions.push(Live { session, request }),
            Err(e) => tracing::error!(error = %e, "Could not open session window"),
        }
    }

    fn reap_sessions(&mut self, event_loop: &ActiveEventLoop) {
        let mut reconnect = Vec::new();
        self.sessions.retain_mut(|live| {
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
            if let Err(e) = self.open_manager(event_loop) {
                tracing::error!(error = %e, "Cannot open main window");
                event_loop.exit();
                return;
            }
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
                    if let Err(e) = self.open_manager(event_loop) {
                        tracing::error!(error = %e, "Cannot reopen main window");
                    }
                }
            },
            UserEvent::Wake => {}
        }
        for live in &mut self.sessions {
            live.session.poll(event_loop);
            if live.session.handle.frame.needs_present.load(std::sync::atomic::Ordering::Acquire) {
                live.session.request_redraw();
            }
        }
        if let Some(w) = &self.manager_win {
            w.window.request_redraw();
        }
        self.reap_sessions(event_loop);
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        let Some(gpu) = self.gpu.as_ref() else { return };

        if self.manager_win.as_ref().is_some_and(|w| w.window.id() == id) {
            let win = self.manager_win.as_mut().expect("checked");
            let resp = win.egui.on_window_event(&win.window, &event);
            if resp.repaint {
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
            live.session.window_event(gpu, id, &event);
        }
        self.reap_sessions(event_loop);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let mut deadline: Option<Instant> = None;
        for live in &mut self.sessions {
            live.session.poll(event_loop);
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
