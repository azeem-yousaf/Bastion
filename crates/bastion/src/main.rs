//! Bastion — Remote Desktop client.
//!
//! Usage: `bastion [FILE.rdp]`

use bastion::app;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::Context as _;
use bastion_core::AppPaths;
use winit::event_loop::EventLoopProxy;

/// Zeroes freed memory while a password prompt is open (see `bastion::wipe`).
#[global_allocator]
static ALLOC: bastion::wipe::WipingAllocator = bastion::wipe::WipingAllocator::new();

fn main() -> anyhow::Result<()> {
    let mut import = None;
    for arg in std::env::args_os().skip(1) {
        match arg.to_str() {
            Some("--version" | "-V") => {
                println!("bastion {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            Some("--help" | "-h") => {
                println!(
                    "Bastion {} — secure Remote Desktop client\n\nUsage: bastion [FILE.rdp]\n\nEnvironment:\n  BASTION_LOG=debug   more detailed logs\n  BASTION_NO_HWDEC=1  disable hardware video decoding\n  BASTION_METRICS=30  performance summary every 30 s (default 10; off to disable)",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => import = Some(PathBuf::from(arg)),
        }
    }

    // Already running (usually in the system tray)? Hand the request over and exit, before
    // touching logs or settings.
    let primary = match bastion::single::runtime_dir() {
        Some(dir) => match bastion::single::acquire(&dir, &bastion::single::Request::from_launch(import.as_deref())) {
            Ok(bastion::single::Startup::Forwarded) => return Ok(()),
            Ok(bastion::single::Startup::Primary(primary)) => Some(primary),
            Err(e) => {
                eprintln!("bastion: single-instance check failed ({e}); starting a separate instance");
                None
            }
        },
        None => None,
    };
    // Serve later launches right away, before the rest of startup: requests queue here and are
    // handled once the main window is up. A launch that has to wait for a slow start would
    // otherwise give up and start a second instance.
    let wake: Arc<OnceLock<EventLoopProxy<app::UserEvent>>> = Arc::default();
    let launches = primary.map(|primary| {
        let (tx, rx) = std::sync::mpsc::channel();
        let wake = wake.clone();
        primary.serve(move |request| {
            if tx.send(request).is_ok()
                && let Some(proxy) = wake.get()
            {
                let _ = proxy.send_event(app::UserEvent::Launched);
            }
        });
        rx
    });

    let paths = AppPaths::discover()?;
    let settings = bastion_core::store::AppSettings::load(&paths);
    let _log = bastion_core::logging::init(&paths, &settings.log_level)?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Bastion starting");
    if let Some(interval) = bastion_metrics::interval_from_env() {
        bastion_metrics::start_reporter(interval);
    }
    bastion_session::tls::install_default_crypto_provider();
    harden_process();

    let event_loop =
        winit::event_loop::EventLoop::<app::UserEvent>::with_user_event().build().context("create event loop")?;
    // Requests that arrived before this are picked up when the main window opens.
    let _ = wake.set(event_loop.create_proxy());
    let mut app = app::App::new(paths, event_loop.create_proxy(), import, launches)?;
    event_loop.run_app(&mut app).context("event loop")?;
    tracing::info!("Bastion exiting");
    Ok(())
}

/// Defence in depth: no core dumps (they could contain passwords) and no ptrace by other
/// same-user processes reading our memory via /proc.
fn harden_process() {
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
