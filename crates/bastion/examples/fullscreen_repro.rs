//! Diagnostic: reproduces "minimise then restore loses full screen" on a real compositor.
//!
//! Opens a full-screen window per monitor, minimises them, asks KWin (via scripting) to
//! restore them like a taskbar click would, and logs every window event plus final state.
//! Run: cargo run -p bastion --example fullscreen_repro

use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion::gpu::{Gpu, WindowGfx};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::platform::wayland::WindowAttributesExtWayland as _;
use winit::window::{Fullscreen, Window, WindowId};

#[derive(Default)]
struct Repro {
    gpu: Option<Gpu>,
    views: Vec<(WindowGfx, Fullscreen)>,
    start: Option<Instant>,
    phase: u8,
    reapply: bool,
}

const KWIN_RESTORE: &str = r#"
for (const w of workspace.windowList()) {
    if (w.resourceClass == "bastion-repro" && (!ONLY_ONE || w.output.name == "DP-1")) { w.minimized = false; workspace.activeWindow = w; }
}
"#;

fn kwin_restore() {
    let path = std::env::temp_dir().join("bastion-repro-restore.js");
    let only_one = std::env::var_os("RESTORE_ONE").is_some();
    std::fs::write(&path, format!("const ONLY_ONE = {only_one};\n{KWIN_RESTORE}")).unwrap();
    let out = std::process::Command::new("qdbus6")
        .args(["org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting.loadScript"])
        .arg(&path)
        .arg("bastion-repro")
        .output()
        .unwrap();
    let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    println!("[restore] kwin script id={id}");
    let _ = std::process::Command::new("qdbus6")
        .args(["org.kde.KWin", &format!("/Scripting/Script{id}"), "org.kde.kwin.Script.run"])
        .status();
    let _ = std::process::Command::new("qdbus6")
        .args(["org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting.unloadScript", "bastion-repro"])
        .status();
}

impl Repro {
    fn t(&self) -> f32 {
        self.start.map_or(0.0, |s| s.elapsed().as_secs_f32())
    }
}

impl ApplicationHandler for Repro {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.gpu.is_some() {
            return;
        }
        self.reapply = std::env::var_os("NO_REAPPLY").is_none();
        self.start = Some(Instant::now());
        for m in el.available_monitors() {
            let fs = Fullscreen::Borderless(Some(m.clone()));
            let w = Arc::new(
                el.create_window(
                    Window::default_attributes()
                        .with_title("Bastion fullscreen repro")
                        .with_name("bastion-repro", "bastion-repro")
                        .with_fullscreen(Some(fs.clone())),
                )
                .unwrap(),
            );
            let gfx = match &self.gpu {
                Some(g) => WindowGfx::new(g, w, None).unwrap(),
                None => {
                    let (g, s) = Gpu::new(w.clone()).unwrap();
                    let gfx = WindowGfx::new(&g, w, Some(s)).unwrap();
                    self.gpu = Some(g);
                    gfx
                }
            };
            println!("[{:.2}] created on {:?}", self.t(), m.name());
            self.views.push((gfx, fs));
        }
        el.set_control_flow(ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(100)));
    }

    fn window_event(&mut self, _el: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        let t = self.t();
        let reapply = self.reapply;
        let gpu = self.gpu.as_ref().unwrap();
        let Some(i) = self.views.iter().position(|(g, _)| g.window.id() == id) else { return };
        let (gfx, fs) = &mut self.views[i];
        match &event {
            WindowEvent::RedrawRequested => {
                gfx.frame(gpu, |ui| {
                    egui::CentralPanel::default_margins().show(ui, |ui| ui.heading("Bastion repro"));
                });
                return;
            }
            WindowEvent::Resized(s) => gfx.resize(gpu, s.width, s.height),
            WindowEvent::Focused(true) if reapply => {
                println!("[{t:.2}] win{i} focused -> re-applying fullscreen + activating siblings");
                gfx.window.set_fullscreen(Some(fs.clone()));
                if self.phase == 2 {
                    // Same mechanism Bastion uses: ask KWin to restore our other windows.
                    bastion::kwin::restore_windows("Bastion fullscreen repro".to_owned());
                }
            }
            _ => {}
        }
        if !matches!(event, WindowEvent::CursorMoved { .. } | WindowEvent::AxisMotion { .. }) {
            println!(
                "[{t:.2}] win{i} {:?} fullscreen={} size={:?}",
                event,
                gfx.window.fullscreen().is_some(),
                gfx.window.inner_size()
            );
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        let t = self.t();
        match self.phase {
            0 if t > 2.0 => {
                println!("[{t:.2}] === minimising all");
                for (g, _) in &self.views {
                    g.window.set_minimized(true);
                }
                self.phase = 1;
            }
            1 if t > 4.0 => {
                println!("[{t:.2}] === KWin restore (like taskbar click)");
                kwin_restore();
                self.phase = 2;
            }
            2 if t > 7.0 => {
                let path = std::env::temp_dir().join("bastion-repro-query.js");
                std::fs::write(&path, r#"for (const w of workspace.windowList()) { if (w.resourceClass == "bastion-repro") { print("BASTION-REPRO-STATE output=" + w.output.name + " minimized=" + w.minimized + " fullScreen=" + w.fullScreen); } }"#).unwrap();
                let out = std::process::Command::new("qdbus6")
                    .args(["org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting.loadScript"])
                    .arg(&path)
                    .arg("bastion-repro-q")
                    .output()
                    .unwrap();
                let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                let _ = std::process::Command::new("qdbus6")
                    .args(["org.kde.KWin", &format!("/Scripting/Script{id}"), "org.kde.kwin.Script.run"])
                    .status();
                let _ = std::process::Command::new("qdbus6")
                    .args(["org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting.unloadScript", "bastion-repro-q"])
                    .status();
                self.phase = 3;
            }
            3 if t > 8.0 => {
                for (i, (g, _)) in self.views.iter().enumerate() {
                    println!(
                        "[{t:.2}] FINAL win{i} fullscreen={} size={:?} monitor={:?}",
                        g.window.fullscreen().is_some(),
                        g.window.inner_size(),
                        g.window.current_monitor().map(|m| m.size())
                    );
                }
                el.exit();
            }
            _ => {}
        }
        el.set_control_flow(ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(100)));
    }
}

fn main() {
    let el = EventLoop::new().unwrap();
    el.run_app(&mut Repro::default()).unwrap();
}
