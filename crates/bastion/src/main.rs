//! Bastion — Remote Desktop client.
//!
//! Usage: `bastion [FILE.rdp]`

use bastion::app;

use std::path::PathBuf;

use anyhow::Context as _;
use bastion_core::AppPaths;

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
                    "Bastion {} — secure Remote Desktop client\n\nUsage: bastion [FILE.rdp]\n\nEnvironment:\n  BASTION_LOG=debug   more detailed logs\n  BASTION_NO_HWDEC=1  disable hardware video decoding",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => import = Some(PathBuf::from(arg)),
        }
    }

    let paths = AppPaths::discover()?;
    let settings = bastion_core::store::AppSettings::load(&paths);
    let _log = bastion_core::logging::init(&paths, &settings.log_level)?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Bastion starting");
    bastion_session::tls::install_default_crypto_provider();
    harden_process();

    let event_loop =
        winit::event_loop::EventLoop::<app::UserEvent>::with_user_event().build().context("create event loop")?;
    let mut app = app::App::new(paths, event_loop.create_proxy(), import)?;
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
