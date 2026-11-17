# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Bastion is a Linux (Wayland/KDE-first) RDP client in Rust built on the IronRDP crates. See README.md for user-facing features and the security model.

## Commands

```bash
./ci.sh                                   # fmt check + clippy -D warnings + builds tools/test-server + all tests
UPDATE_SNAPSHOTS=1 cargo test -p bastion --test ui   # accept intentional UI changes (PNG snapshots in crates/bastion/tests/snapshots)
cargo test -p bastion-session --test loopback <name> # one end-to-end test (builds & spawns tools/test-server)
TEST_SERVER_LOG=debug cargo test -p bastion-session --test loopback   # show the test server's logs
cargo test -p <crate> <test_name>         # single unit/integration test
./install.sh                              # release build + install to ~/.local (desktop file, .rdp MIME); --uninstall
BASTION_LOG=debug bastion                 # verbose logs (also: BASTION_NO_HWDEC=1 to force software H.264)
BASTION_METRICS=5 bastion                 # performance summary line every 5 s (default 10, `off` disables)
cargo run -p bastion --example fullscreen_repro   # Wayland/KWin minimise/restore diagnostic (opens real windows)
```

rustfmt uses `max_width = 120`. Clippy runs with `-D warnings` on all targets, so `ci.sh` fails on any lint. When chaining commands, check `ci.sh`'s exit code before committing (don't pipe it into grep and continue on success).

Logs: `~/.local/state/bastion/logs/` (today plain, earlier days `.log.gz`, deleted after 7 days by `logging::maintain_logs`, run at startup and hourly); config: `~/.config/bastion/{profiles,known_hosts,settings}.toml`; passwords live only in the Secret Service keyring.

## Workspace layout and data flow

- `bastion-metrics` — dependency-free, lock-free counters/histograms (`static`s, one per pipeline stage) recorded on hot paths in every crate; a reporter thread logs one `bastion::metrics` line per interval (nothing when idle, `warn` when a stage crosses its slow threshold). New metrics must be added to the `COUNTERS`/`HISTOGRAMS` lists to be reported. Logging is off-thread and batched (`non_blocking` + `BufWriter`; the worker flushes once per drained batch) — never log per frame/PDU, record a metric instead.
- `bastion-core` — profiles (`Profile`), TOML storage (0600, atomic writes), keyring secrets (`Secret` zeroizes, redacted Debug), certificate pin store (`TrustStore`), `.rdp` import (UTF-16 decoding), logging with secret redaction.
- `bastion-session` — the connection engine. `SessionHandle::spawn` runs a dedicated thread + Tokio runtime; the UI talks to it only via `Command` (input, layout, clipboard, cert decision, disconnect) and `Event` (status, pointer, cert prompt, notices, disconnected), plus `SharedFrame` (RGBA framebuffer with a dirty rect and a `needs_present` flag used to coalesce wakeups). `engine.rs` builds the IronRDP `ClientConnector` with all channels, connects (direct TCP or `ironrdp_mstsgu` RD Gateway), does TLS via our own verifier, runs the active-session `select!` loop, and handles auto-reconnect with the server's reconnect cookie. Per-session link stats (`link.rs`: byte counters, `TCP_INFO` RTT via a dup of the socket — through a gateway found by its local address in `/proc/self/fd` — and Windows' network auto-detect results) feed the session bar's quality indicator (`bastion::quality`, pure, sampled once a second). Input bypasses that loop (`input_task` writes fast-path input to the shared socket writer) and so does graphics: `gfx.rs` registers a `GfxForwarder` on the EGFX channel and runs IronRDP's `GraphicsPipelineClient` on a `bastion-gfx` thread that writes compositor output straight into `SharedFrame` and returns replies as `Command::GfxReply`. Once that pipeline is active it owns the frame size (`desktop_size`). The H.264 decoder's `supports_yuv420` is a runtime switch: on to advertise V10.x, off after a V10.3+ confirm so AVC420 uses our SIMD conversion, back on (plus a protocol reset) if AVC444 arrives.
- `bastion-video` — FFmpeg `H264Decoder` for `ironrdp-egfx`, low-delay. Sessions use adaptive mode: software first (remote-desktop streams decode in ~1.5 ms on the CPU vs ~14 ms NVDEC + copy-back), moving to NVDEC/VAAPI at the next IDR (requesting one via the graphics reset flag) only if software averages > 16 ms/frame; falls back to software on repeated hw errors. Test fixtures are single-slice x264 streams.
- `bastion-audio` — PulseAudio-protocol playback (`RdpsndClientHandler`) and mic capture (`RdpeaiCaptureHandler`) behind an `AudioHost` trait so tests use in-memory devices; `ConnectParams::audio_host` injects one into the engine.
- `bastion-camera` — webcam redirection (MS-RDPECAM via `ironrdp-rdpecam`). `CameraHost` trait (V4L2 in production, fakes in tests); `RdpCamera` is the `CameraBackend`. MJPG frames pass through untouched (YUYV only for MJPG-less cameras, ≤640×480), 30 fps cap; samples go up the same uplink channel as the mic. Real-camera smoke test: `cargo test -p bastion-camera --test hardware -- --ignored`.
- `bastion-clipboard` — custom CLIPRDR backend (text, HTML, images, files both ways); one worker thread owns state; OS layer behind a trait (Wayland data-control first, X11 fallback, in-memory fake for tests).
- `bastion` — the app (lib + thin `main.rs`). Raw `winit` + `wgpu` + `egui` (not eframe — RDP needs raw scancodes). `app.rs` routes events between the manager window and sessions; `session.rs` owns a session's window(s) (one fullscreen window per monitor in all-monitors mode, each showing a region of the remote desktop), input, overlays (cert dialog, status, session bar); `input.rs` is pure, testable input translation; `inhibit.rs` (Wayland shortcut inhibit), `kwin.rs` (KWin scripting), `tray.rs` (StatusNotifierItem).
- `tools/test-server` — **separate Cargo workspace** (ironrdp-server 0.13 is on an older IronRDP stack whose `picky` pin conflicts with ours). It's a loopback RDP server with TLS+NLA that prints input events to stdout and streams a PCM ramp; the loopback tests spawn it. The same test file contains a mock MS-TSGU gateway (TLS, Basic auth, WebSocket transport) relaying to it.

## Non-obvious constraints (learned the hard way)

- `vendor/ironrdp-graphics` (parallel RemoteFX Progressive, fast ZGFX) and `vendor/ironrdp-egfx` (AVC420 direct blit, `wants_bitmap_data`) are patched copies wired in with `[patch.crates-io]`; see `vendor/README.md`. They're excluded from the workspace — `ci.sh` runs their tests via `--manifest-path`. Upgrading IronRDP means re-applying `vendor/*.patch`. Performance work: record a session with `BASTION_GFX_CAPTURE=<dir>`, replay with `examples/gfx_replay.rs` (prints per-codec timings and pixel checksums; compare checksums before/after with `BASTION_NO_HWDEC=1`).
- Keep IronRDP crate versions mutually compatible; `sspi` is pinned `=0.23.0` to match `picky =7.0.0-rc.26`.
- IronRDP's TLS (gateway and host) accepts any certificate by default. Bastion always uses `tls::PinningVerifier` (WebPKI → user pin → prompt). Rejections surface as `ConnectFailure::Certificate` → `Event::CertificatePrompt`, and the engine retries after the user decides.
- Windows only starts "Remote Audio" playback if an RDPDR (device redirection) channel exists, so `build_connector` always attaches one (no devices) when audio is enabled.
- Windows closes and reopens all dynamic channels when logon hands over to the desktop. A processor registered with `DrdynvcClient::with_dynamic_channel` can only be opened once (the reopen gets NO_LISTENER), so channels Windows may open early (e.g. the camera enumerator) must use `with_dynamic_channel_factory` or a listener.
- Windows advertises audio as `WAVE_FORMAT_EXTENSIBLE`; use `bastion_audio::format::normalize`. For the mic, Windows typically opens with a PCM 44.1 kHz stereo *capture* format but an MS-ADPCM 22.05 kHz mono *encode* format — capture must be opened in the encode shape (`rescale_packet` keeps packet duration), and `set_format` must restart capture on rate/channel changes rather than refuse.
- egui 0.37: enable `default_fonts` + `monochrome_emoji_fonts`; glyphs outside those fonts panic in tests. Texture deltas must be applied even when a frame is skipped. kittest enforces accessible labels (form widgets use `labelled_by`).
- wgpu must be created with the event loop's `OwnedDisplayHandle`, never a window (it would keep that window alive forever).
- Monitor hot-plug: winit has no monitor-change event, so `App::watch_monitors` compares `monitors::snapshot` (keyed by connector name, e.g. `DP-1`, which profiles store) on every `about_to_wait` and acts after it is stable for 1.5 s. Sessions re-create their windows (`Session::reconfigure`) and send `Command::Layout` without reconnecting; decisions live in the pure `monitors::plan`. Window creation needs the event loop, so UI actions only set flags applied in `apply_monitor_changes`.
- Wayland: apps can't un-minimise their own windows, and per-monitor session windows minimise independently; restoring siblings goes through KWin scripting (`kwin::restore_windows`, matched by PID + exact title). winit reports monitor positions as logical position × *integer* scale; mixed-DPI layouts are built with `layout::pack_monitors` (edge-to-edge in pixels).
- The session bar reveals only at the top-centre edge in fullscreen and only its own rect captures input (`session::bar_on_pointer`); corners belong to the remote desktop.
- User-facing errors must be friendly and contain no source paths (`friendly_connector_error`, `gateway_error_message`); full detail goes to the log only.
