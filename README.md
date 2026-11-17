# Bastion

A fast, secure Remote Desktop (RDP) client for Linux, written in Rust. It is built for
connecting to Windows PCs through a **Remote Desktop Gateway**.

- **Full desktop:** keyboard (scancode-exact, any layout), mouse, smooth and horizontal
  scrolling, and remote cursors.
- **Audio both ways:** remote sound plays on your speakers or headset, and your microphone
  is available in the remote session. Devices are chosen by name (PipeWire/PulseAudio).
- **Clipboard sync:** text, rich text (HTML), images, and files.
- **RD Gateway** (HTTPS / WebSocket transport, NTLM/Negotiate) or direct connections.
- **Efficient graphics:** the RDP graphics pipeline decoded off the session thread: H.264/AVC
  in software on all cores (faster than a GPU round trip for remote-desktop content), switching
  to **hardware decoding** (NVDEC on NVIDIA, VAAPI elsewhere) when video gets too heavy;
  RemoteFX Progressive tiles decoded in parallel. Only changed screen regions are copied and
  uploaded to the GPU.
- **Dynamic resolution:** resize the window and the remote desktop follows, including HiDPI
  scaling.
- **Multi-monitor:** full screen across every monitor (or the ones you pick per connection), one
  borderless window per screen. Unplugging a monitor keeps the session on the others; plugging
  one in asks whether to extend the session onto it.
- **Connection speed** per connection: let Windows detect it, or pick Local network, Broadband
  (no wallpaper) or Low bandwidth (no wallpaper, animations or transparency) for slow links.
- **Folder sharing** (off by default), optionally read-only.
- **Connection quality indicator** in the session bar: a green / amber / red dot with the
  latency; hover for packet loss, frame rate and bandwidth. A notice appears if the connection
  stays poor.
- **Wake-on-LAN:** a *Wake* button per connection, and automatic waking when a sleeping
  computer doesn't answer (enter its MAC address, or click *Detect* while it is on).
- **Auto-reconnect** after network drops, using the server's reconnect cookie.
- **.rdp import:** open company `.rdp` files directly, or double-click them in Dolphin.
- **System shortcuts** (Alt+Tab, Super, Alt+F4) go to the remote PC while it has focus.

## Install

Requirements (Arch/CachyOS): `rust`, `ffmpeg`, `libpulse` (provided by PipeWire), plus a
desktop keyring such as KWallet or GNOME Keyring.

```bash
./install.sh            # builds a release binary, installs to ~/.local, registers .rdp files
./install.sh --uninstall
```

## Using it

1. Open **Bastion** from the app launcher, or run `bastion` or `bastion work.rdp`.
2. Click **New connection** (or **Import .rdp file…**), enter the computer name, then tick
   *Connect through a Remote Desktop Gateway* and enter the gateway host.
3. Click **Connect** and sign in. Tick *Remember password* to store it in the system keyring.

| Action | How |
| --- | --- |
| Release the keyboard / show the session bar | **Ctrl+Alt+Home** |
| Send Ctrl+Alt+Del | Session bar → *Ctrl+Alt+Del* |
| Toggle full screen | Session bar → *Full screen* |
| Recapture the keyboard | Click inside the remote desktop |

In full screen, move the mouse to the top edge to reveal the session bar. Click *Pin* on it to keep
it visible (remembered for later sessions); *Unpin* lets it hide again.

## Security model

- **Certificates are verified.** IronRDP accepts any certificate by default; Bastion does not.
  - Gateway and host certificates are checked against the system CAs and the hostname.
  - A self-signed certificate (common on RDP hosts) is shown with its SHA-256 fingerprint for
    you to approve once (trust on first use), after which it is pinned.
  - If a pinned certificate changes, Bastion shows a prominent warning and requires explicit
    confirmation.
  - The per-connection *Skip certificate verification* switch exists for isolated labs only.
- **Network Level Authentication (CredSSP)** is required, so your password is never sent
  to an unauthenticated server. A computer (or anything on the network path) that tries to
  fall back to TLS-only sign-in is refused before any credentials leave your machine.
- **Passwords** live only in the OS keyring (Secret Service).
  - They are never written to Bastion's files.
  - Bastion wipes its own copies from memory when they are no longer needed (the protocol
    libraries keep an unwiped copy while a connection is open).
  - They are never logged, whatever the log level: the sign-in libraries' debug output is
    always suppressed, and logs are additionally scrubbed for secret-looking values. Log
    files are readable only by you.
- **Imported `.rdp` files** never switch on folder or webcam sharing; the import tells you
  what it left off and which gateway would receive your credentials.
- **One instance:** starting Bastion again (or opening a `.rdp` file) while it is running
  shows the running instance's window instead of starting a second copy.
- **Process hardening:** core dumps are disabled and the process is non-dumpable, so other
  processes cannot read its memory.
- **Folder sharing** is off by default.
  - Shared folders are sandboxed: no `..`, no following symlinks, and no crossing mount points.
  - *Read-only* mode refuses every modifying request at the protocol level.
- **Clipboard file transfers** are size-limited and path-sanitised (hidden-file names from
  the remote side arrive with a visible name). Selections that a password manager marks as
  secret are never offered to a remote computer.
- **No telemetry:** nothing is ever sent anywhere except to your gateway and PC.

Configuration lives in `~/.config/bastion/` (mode 0700): `profiles.toml` and
`known_hosts.toml`. Logs are in `~/.local/state/bastion/logs/`: today's as plain text, earlier days gzip-compressed
(`zless` reads them), deleted after 7 days.

## Troubleshooting

- **"Sign-in failed"**: check the username and domain (`CORP` + `alice`, or `alice@corp.com`).
  Bastion forgets a remembered password after a failed sign-in.
- **Gateway HTTP 401/403**: your account isn't allowed through the gateway, or the gateway
  needs separate credentials. Untick *Use the same credentials…* and enter them.
- **No sound or microphone**: check the device pickers under *Audio & devices*. On the
  Windows side, the policy *Allow audio and video playback/recording redirection* must be
  enabled.
- **Video glitches**: run with `BASTION_NO_HWDEC=1` to force software decoding, or untick
  *H.264* in the connection's Display settings.
- **Wake-on-LAN doesn't wake the computer**: enable Wake-on-LAN in its BIOS/UEFI and in the
  network adapter's power settings (Windows: *Allow this device to wake the computer* and
  *Only allow a magic packet…*). The packet is a local-network broadcast, so it can't cross a
  router or an RD Gateway; on another subnet, set that subnet's broadcast address.
- **More detail**: run with `BASTION_LOG=debug bastion`, or see the log folder (*Settings →
  Diagnostics → Open folder*).
- **Slowness**: every 10 s while something is happening, the log gets one `bastion::metrics`
  line with throughput and timing percentiles for each stage (network, PDU processing, H.264
  decode, screen upload/render, input latency, audio). It is logged as a warning, naming the
  stage, when a stage exceeded its "slow" threshold. `BASTION_METRICS=30` changes the interval,
  `BASTION_METRICS=off` disables it. Metrics cost a few atomic operations per event and write
  nothing while idle.

## Development

```bash
./ci.sh                         # fmt + clippy (deny warnings) + full test suite
UPDATE_SNAPSHOTS=1 ./ci.sh      # accept intentional UI changes
TEST_SERVER_LOG=debug cargo test -p bastion-session --test loopback   # see server-side logs
```

The test suite covers:

- **Unit tests** in every crate: profiles, .rdp import, trust store, log redaction, keyboard
  mapping, layouts, input translation, audio negotiation, buffering and volume, the mic
  encoder, read-only policy, and H.264 decoding (with checked-in fixtures, comparing hardware
  and software output pixel by pixel).
- **Loopback end-to-end tests:** a real RDP server (`tools/test-server`, TLS + NLA) is
  started, and Bastion's real engine is checked for:
  - certificate prompts, pinning, MITM detection and insecure mode;
  - graphics, keyboard (including extended keys), mouse;
  - bit-exact audio playback;
  - wrong-password handling, auto-reconnect, and unreachable hosts.
- **UI tests** (egui_kittest): real clicks and typing in the manager, validation, import, the
  credential prompt, and certificate dialogs. These include accessibility checks and pixel
  snapshot comparisons.

### Architecture

| Crate | Responsibility |
| --- | --- |
| `bastion-core` | Profiles, storage, keyring secrets, certificate pins, .rdp import, logging |
| `bastion-session` | Connection engine (gateway, TLS policy, NLA, session loop, reconnect), keyboard mapping, drive policy |
| `bastion-video` | FFmpeg H.264 decoder (NVDEC/VAAPI/software) for the RDP graphics pipeline |
| `bastion-audio` | Native PulseAudio/PipeWire playback and microphone capture |
| `bastion-clipboard` | Clipboard redirection (Wayland data-control with X11 fallback) |
| `bastion` | The app: winit + wgpu + egui UI, connection manager, session windows |

The protocol stack is [IronRDP](https://github.com/Devolutions/IronRDP) (pure Rust).
