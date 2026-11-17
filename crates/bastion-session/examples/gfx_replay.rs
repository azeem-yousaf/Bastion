//! Replays a graphics-channel recording through Bastion's real pipeline and prints timings.
//!
//! Record (contains your screen contents; stays on this machine):
//!   BASTION_GFX_CAPTURE=~/bastion-capture bastion
//! Replay:
//!   cargo run --release -p bastion-session --example gfx_replay -- ~/bastion-capture/gfx-*.bin

use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let display = bastion_core::profile::DisplaySettings::default();
    for path in std::env::args_os().skip(1) {
        let path = std::path::PathBuf::from(path);
        let _ = bastion_metrics::collect(Duration::from_secs(1));
        let stats = bastion_session::gfx::replay_capture(&path, &display)?;
        println!(
            "{}: {} messages, {:.1} MB, {:.0} ms in the pipeline",
            path.display(),
            stats.messages,
            stats.bytes as f64 / 1e6,
            stats.busy.as_secs_f64() * 1e3
        );
        println!(
            "  final frame {}x{} checksum {:016x}, all updates checksum {:016x}",
            stats.frame_size.0, stats.frame_size.1, stats.frame_checksum, stats.updates_checksum
        );
        if let Some(r) = bastion_metrics::collect(stats.busy.max(Duration::from_millis(1))) {
            for part in r
                .line
                .split("ms ")
                .filter(|p| p.starts_with("gfx.") || p.starts_with("frame.") || p.starts_with("video."))
            {
                println!("  {}ms", part.trim_end_matches("ms"));
            }
        }
    }
    Ok(())
}
