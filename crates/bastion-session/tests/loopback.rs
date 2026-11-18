//! End-to-end tests: Bastion's real session engine against a local RDP server
//! (`tools/test-server`, built automatically) over TLS + NLA.

use std::io::BufRead as _;
use std::process::{Child, Command as Proc, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bastion_core::profile::{KeepActive, Profile};
use bastion_core::secrets::Secret;
use bastion_core::trust::{EndpointKind, TrustStore};
use bastion_session::{Command, ConnectParams, DesktopLayout, Event, SessionHandle, Status};
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode};

const USER: &str = "tester";
const PASSWORD: &str = "Passw0rd!";
const TIMEOUT: Duration = Duration::from_secs(30);

fn server_binary() -> &'static std::path::Path {
    static BIN: OnceLock<std::path::PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/test-server");
        let status = Proc::new(env!("CARGO"))
            .args(["build", "--quiet", "--manifest-path"])
            .arg(root.join("Cargo.toml"))
            .status()
            .expect("run cargo to build the test server");
        assert!(status.success(), "building tools/test-server failed");
        root.join("target/debug/bastion-test-server")
    })
}

struct Server {
    child: Child,
    port: u16,
    fingerprint: String,
    log: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start() -> Self {
        let mut child = Proc::new(server_binary())
            .args(["--user", USER, "--password", PASSWORD])
            .stdout(Stdio::piped())
            .stderr(if std::env::var_os("TEST_SERVER_LOG").is_some() { Stdio::inherit() } else { Stdio::null() })
            .spawn()
            .expect("spawn test server");
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut port = 0;
        let mut fingerprint = String::new();
        while port == 0 || fingerprint.is_empty() {
            let line = lines.next().expect("server exited early").unwrap();
            if let Some(p) = line.strip_prefix("LISTENING ") {
                port = p.parse().unwrap();
            } else if let Some(f) = line.strip_prefix("CERT_SHA256 ") {
                fingerprint = f.to_owned();
            }
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                l.lock().unwrap().push(line);
            }
        });
        // Wait until the port accepts connections.
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "server never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child, port, fingerprint, log }
    }

    fn saw(&self, needle: &str) -> bool {
        self.log.lock().unwrap().iter().any(|l| l == needle)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn profile(port: u16) -> Profile {
    let mut p = Profile {
        name: "loopback".into(),
        host: "127.0.0.1".into(),
        port,
        username: USER.into(),
        ..Default::default()
    };
    // Keep tests hermetic: don't touch the developer's real clipboard / speakers / mic.
    p.clipboard.enabled = false;
    p.audio.playback = false;
    p.audio.microphone = false;
    p.display.h264 = false;
    p.reconnect.max_attempts = 3;
    p
}

fn connect(p: Profile, password: &str, trust: Arc<Mutex<TrustStore>>) -> SessionHandle {
    connect_with_audio(p, password, trust, None)
}

fn connect_with_audio(
    p: Profile,
    password: &str,
    trust: Arc<Mutex<TrustStore>>,
    audio_host: Option<Arc<dyn bastion_audio::AudioHost>>,
) -> SessionHandle {
    connect_with_hosts(p, password, trust, audio_host, None)
}

fn connect_with_hosts(
    p: Profile,
    password: &str,
    trust: Arc<Mutex<TrustStore>>,
    audio_host: Option<Arc<dyn bastion_audio::AudioHost>>,
    camera_host: Option<Arc<dyn bastion_camera::CameraHost>>,
) -> SessionHandle {
    SessionHandle::spawn(
        ConnectParams {
            profile: p,
            password: Secret::new(password.into()),
            gateway_password: None,
            layout: DesktopLayout::single(640, 480, 100),
            trust,
            keyboard_layout: 0x0809,
            client_name: "bastion-test".into(),
            audio_host,
            camera_host,
        },
        Arc::new(|| {}),
    )
}

/// Polls events until `pred` returns Some, collecting everything seen.
fn wait_event<T>(h: &SessionHandle, mut pred: impl FnMut(&Event) -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        while let Some(ev) = h.try_event() {
            if let Some(v) = pred(&ev) {
                return v;
            }
            if let Event::Disconnected { reason, .. } = &ev {
                panic!("unexpected disconnect: {reason}");
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for event");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_disconnect(h: &SessionHandle) -> (String, bool) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        while let Some(ev) = h.try_event() {
            if let Event::Disconnected { reason, error } = ev {
                return (reason, error);
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for disconnect");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn centre_pixel(h: &SessionHandle) -> Option<[u8; 3]> {
    let f = h.frame.lock();
    if f.width != 640 {
        return None;
    }
    let off = ((240 * 640) + 320) * 4;
    Some([f.data[off], f.data[off + 1], f.data[off + 2]])
}

fn pinned_trust(server: &Server) -> Arc<Mutex<TrustStore>> {
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    let h = connect(profile(server.port), PASSWORD, trust.clone());
    wait_event(&h, |e| matches!(e, Event::CertificatePrompt(_)).then_some(()));
    h.send(Command::CertificateDecision { accept: true });
    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));
    drop(h);
    trust
}

#[test]
fn unknown_certificate_prompts_and_decline_aborts() {
    let server = Server::start();
    let h = connect(profile(server.port), PASSWORD, Arc::new(Mutex::new(TrustStore::in_memory())));
    let rej = wait_event(&h, |e| match e {
        Event::CertificatePrompt(r) => Some(r.clone()),
        _ => None,
    });
    assert_eq!(rej.kind, EndpointKind::Rdp);
    assert_eq!(rej.fingerprint, server.fingerprint, "prompt must show the real server fingerprint");
    assert!(rej.previous_fingerprint.is_none());
    h.send(Command::CertificateDecision { accept: false });
    let (reason, error) = wait_disconnect(&h);
    assert!(error && reason.contains("certificate"), "{reason}");
}

#[test]
fn full_session_graphics_keyboard_and_mouse() {
    let server = Server::start();
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    let h = connect(profile(server.port), PASSWORD, trust.clone());

    wait_event(&h, |e| matches!(e, Event::CertificatePrompt(_)).then_some(()));
    h.send(Command::CertificateDecision { accept: true });
    let (w, ht) = wait_event(&h, |e| match e {
        Event::Status(Status::Connected { width, height }) => Some((*width, *height)),
        _ => None,
    });
    assert_eq!((w, ht), (640, 480));

    // Initial desktop is red.
    wait_until("red desktop", || centre_pixel(&h).is_some_and(|p| p[0] > 180 && p[1] < 40));

    // Keyboard: 'A' turns the server desktop green.
    let mut db = Database::new();
    let a = Scancode::from_u8(false, 0x1E);
    h.send(Command::Input(db.apply([Operation::KeyPressed(a)])));
    h.send(Command::Input(db.apply([Operation::KeyReleased(a)])));
    wait_until("green desktop after key press", || centre_pixel(&h).is_some_and(|p| p[1] > 180 && p[0] < 40));
    assert!(server.saw("KEY DOWN 30 false"));
    wait_until("key release", || server.saw("KEY UP 30 false"));

    // Extended key (Right Ctrl) keeps the E0 flag.
    let rctrl = Scancode::from_u8(true, 0x1D);
    h.send(Command::Input(db.apply([Operation::KeyPressed(rctrl), Operation::KeyReleased(rctrl)])));
    wait_until("extended key", || server.saw("KEY DOWN 29 true"));

    // Mouse.
    h.send(Command::Input(db.apply([
        Operation::MouseMove(MousePosition { x: 100, y: 200 }),
        Operation::MouseButtonPressed(MouseButton::Left),
        Operation::MouseButtonReleased(MouseButton::Left),
        Operation::MouseButtonPressed(MouseButton::Right),
        Operation::MouseButtonReleased(MouseButton::Right),
    ])));
    wait_until("mouse move", || server.saw("MOUSE MOVE 100 200"));
    wait_until("left click", || server.saw("MOUSE LEFT DOWN") && server.saw("MOUSE LEFT UP"));
    wait_until("right click", || server.saw("MOUSE RIGHT DOWN") && server.saw("MOUSE RIGHT UP"));

    // Accepted certificate is now pinned.
    let pins = trust.lock().unwrap().entries().count();
    assert_eq!(pins, 1);

    // Performance metrics saw the network, PDU processing, screen updates and input latency.
    let report = bastion_metrics::collect(Duration::from_secs(1)).expect("metrics recorded");
    println!("metrics: {}", report.line);
    for part in ["net.rx=", "net.pdus=", "rdp.process[", "frame.updates=", "input.queue[", "input.latency["] {
        assert!(report.line.contains(part), "missing {part} in {}", report.line);
    }

    // The connection quality indicator has traffic, frames and a kernel round-trip time.
    let link = h.link.sample(&h.frame);
    assert!(link.rx_bytes > 10_000 && link.tx_bytes > 0, "{link:?}");
    assert!(link.frames >= 2, "{link:?}");
    assert!(!link.via_gateway);
    let tcp = link.tcp.expect("direct connection has a TCP probe");
    assert!(tcp.segs_out > 0 && tcp.rtt < Duration::from_millis(100), "{tcp:?}");

    // User disconnect is a clean, non-error end.
    h.send(Command::Disconnect);
    let (_, error) = wait_disconnect(&h);
    assert!(!error);
}

/// Keep-active nudges the remote mouse one pixel and back once the session has been idle for the
/// configured time (30 s — the shortest real setting), and not before.
#[test]
fn keep_active_nudges_mouse_after_idle_interval() {
    let server = Server::start();
    let mut p = profile(server.port);
    p.keep_active = KeepActive::Secs30;
    let h = connect(p, PASSWORD, pinned_trust(&server));
    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));

    let mut db = Database::new();
    h.send(Command::Input(db.apply([Operation::MouseMove(MousePosition { x: 100, y: 200 })])));
    let moved = Instant::now();
    wait_until("user mouse move", || server.saw("MOUSE MOVE 100 200"));

    let deadline = moved + Duration::from_secs(45);
    while !server.saw("MOUSE MOVE 101 200") {
        assert!(Instant::now() < deadline, "no keep-active nudge within 45 s");
        std::thread::sleep(Duration::from_millis(50));
    }
    let after = moved.elapsed();
    assert!(after >= Duration::from_secs(29), "nudged too early: {after:?}");
    // ...and returned the cursor to where it was.
    wait_until("cursor returned", || {
        let log = server.log.lock().unwrap();
        let nudge = log.iter().position(|l| l == "MOUSE MOVE 101 200").unwrap();
        log[nudge..].iter().any(|l| l == "MOUSE MOVE 100 200")
    });

    h.send(Command::Disconnect);
    assert!(!wait_disconnect(&h).1);
}

/// In-memory camera host: lists the given cameras; the test server never opens them.
struct FakeCameras(Vec<bastion_camera::CameraInfo>);

impl bastion_camera::CameraHost for FakeCameras {
    fn cameras(&self) -> Vec<bastion_camera::CameraInfo> {
        self.0.clone()
    }
    fn start(
        &self,
        _: &bastion_camera::CameraInfo,
        _: bastion_camera::Mode,
        _: bastion_camera::FrameCallback,
    ) -> anyhow::Result<Box<dyn bastion_camera::RunningCapture>> {
        anyhow::bail!("not used by the test server")
    }
}

/// Camera redirection registers its channels without disturbing the session, and tells the user
/// when there's no camera to share. (The RDPECAM message flow itself is tested in bastion-camera.)
#[test]
fn camera_redirection_connects_with_and_without_cameras() {
    let server = Server::start();
    let mut p = profile(server.port);
    p.camera.enabled = true;

    let none = Arc::new(FakeCameras(Vec::new()));
    let h = connect_with_hosts(p.clone(), PASSWORD, pinned_trust(&server), None, Some(none));
    wait_event(&h, |e| match e {
        Event::Notice(n) if n.contains("No webcam") => Some(()),
        _ => None,
    });
    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));
    h.send(Command::Disconnect);
    assert!(!wait_disconnect(&h).1);

    let cam = bastion_camera::CameraInfo {
        id: "fake0".into(),
        name: "Fake Cam".into(),
        modes: vec![bastion_camera::Mode {
            format: bastion_camera::PixelFormat::Mjpeg,
            width: 1280,
            height: 720,
            fps_num: 30,
            fps_den: 1,
        }],
    };
    let h = connect_with_hosts(p, PASSWORD, pinned_trust(&server), None, Some(Arc::new(FakeCameras(vec![cam]))));
    wait_event(&h, |e| match e {
        Event::Status(Status::Connected { .. }) => Some(()),
        Event::Notice(n) => panic!("unexpected notice: {n}"),
        _ => None,
    });
    // Input still flows normally.
    let mut db = Database::new();
    let a = Scancode::from_u8(false, 0x1E);
    h.send(Command::Input(db.apply([Operation::KeyPressed(a), Operation::KeyReleased(a)])));
    wait_until("key press with camera channels registered", || server.saw("KEY DOWN 30 false"));
    h.send(Command::Disconnect);
    assert!(!wait_disconnect(&h).1);
}

#[test]
fn pinned_certificate_connects_without_prompt() {
    let server = Server::start();
    let trust = pinned_trust(&server);
    let h = connect(profile(server.port), PASSWORD, trust);
    wait_event(&h, |e| match e {
        Event::CertificatePrompt(_) => panic!("pinned certificate must not prompt again"),
        Event::Status(Status::Connected { .. }) => Some(()),
        _ => None,
    });
}

#[test]
fn changed_certificate_is_flagged_as_possible_mitm() {
    let server = Server::start();
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    trust
        .lock()
        .unwrap()
        .pin(EndpointKind::Rdp, &format!("127.0.0.1:{}", server.port), b"some other certificate")
        .unwrap();
    let h = connect(profile(server.port), PASSWORD, trust);
    let rej = wait_event(&h, |e| match e {
        Event::CertificatePrompt(r) => Some(r.clone()),
        _ => None,
    });
    assert!(rej.previous_fingerprint.is_some(), "must report the previously pinned fingerprint");
}

#[test]
fn wrong_password_fails_cleanly_without_retry_loop() {
    let server = Server::start();
    let trust = pinned_trust(&server);
    let h = connect(profile(server.port), "wrong-password", trust);
    let mut statuses = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    let (reason, error) = loop {
        match h.try_event() {
            Some(Event::Disconnected { reason, error }) => break (reason, error),
            Some(Event::Status(s)) => statuses.push(s),
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no disconnect");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    assert!(error);
    assert!(!statuses.iter().any(|s| matches!(s, Status::Connected { .. })), "must not connect: {statuses:?}");
    assert!(
        !statuses.iter().any(|s| matches!(s, Status::Reconnecting { .. })),
        "bad credentials must not trigger reconnects"
    );
    assert!(reason.starts_with("Sign-in failed"), "{reason}");
    assert!(!reason.contains(".rs:"), "no source paths in user messages: {reason}");
}

#[test]
fn insecure_mode_skips_certificate_prompt() {
    let server = Server::start();
    let mut p = profile(server.port);
    p.security.allow_insecure_tls = true;
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    let h = connect(p, PASSWORD, trust.clone());
    wait_event(&h, |e| match e {
        Event::CertificatePrompt(_) => panic!("insecure mode must not prompt"),
        Event::Status(Status::Connected { .. }) => Some(()),
        _ => None,
    });
    assert_eq!(trust.lock().unwrap().entries().count(), 0, "insecure mode must not pin anything");
}

#[test]
fn connection_loss_triggers_auto_reconnect() {
    let mut server = Server::start();
    let trust = pinned_trust(&server);
    let h = connect(profile(server.port), PASSWORD, trust);
    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));
    server.child.kill().unwrap();
    let attempt = wait_event(&h, |e| match e {
        Event::Status(Status::Reconnecting { attempt, .. }) => Some(*attempt),
        _ => None,
    });
    assert_eq!(attempt, 1);
    // Server is gone for good: the engine gives up after max_attempts and reports an error.
    let (reason, error) = wait_disconnect(&h);
    assert!(error, "{reason}");
}

/// A server (or someone on the path) that answers the security negotiation with "TLS only"
/// must not get a TLS handshake, let alone the password in the Client Info PDU.
#[test]
fn tls_only_downgrade_is_refused_before_anything_is_sent() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(TIMEOUT)).unwrap();
        // X.224 Connection Request: TPKT header (length at bytes 2..4), then the rest.
        let mut header = [0u8; 4];
        s.read_exact(&mut header).unwrap();
        let mut rest = vec![0u8; usize::from(u16::from_be_bytes([header[2], header[3]])) - 4];
        s.read_exact(&mut rest).unwrap();
        // X.224 Connection Confirm with RDP_NEG_RSP selecting PROTOCOL_SSL (0x1): no CredSSP.
        s.write_all(&[
            0x03, 0x00, 0x00, 0x13, // TPKT, 19 bytes
            0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // X.224 CC
            0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, // RDP_NEG_RSP, selectedProtocol = SSL
        ])
        .unwrap();
        // Everything the client sends from here on (a TLS ClientHello would be the first thing).
        let mut after = Vec::new();
        let _ = s.read_to_end(&mut after);
        let _ = seen_tx.send(after);
    });

    let h = connect(profile(port), PASSWORD, Arc::new(Mutex::new(TrustStore::in_memory())));
    let (reason, error) = wait_disconnect(&h);
    assert!(error);
    assert!(reason.contains("Network Level Authentication"), "{reason}");
    assert!(!reason.contains(".rs"), "{reason}");
    let after = seen_rx.recv_timeout(TIMEOUT).expect("server thread");
    assert!(after.is_empty(), "client kept talking after the downgrade: {} bytes", after.len());
}

#[test]
fn unreachable_host_reports_error() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let h = connect(profile(port), PASSWORD, Arc::new(Mutex::new(TrustStore::in_memory())));
    let (reason, error) = wait_disconnect(&h);
    assert!(error && reason.contains("127.0.0.1"), "{reason}");
}

fn wake_profile(port: u16, rx: &std::net::UdpSocket) -> Profile {
    let mut p = profile(port);
    p.wake.mac = "00:11:22:33:44:55".into();
    p.wake.broadcast = "127.0.0.1".into();
    p.wake.port = rx.local_addr().unwrap().port();
    p
}

#[test]
fn wake_on_lan_is_not_sent_to_a_computer_that_answers() {
    let server = Server::start();
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_nonblocking(true).unwrap();
    let h = connect(wake_profile(server.port, &rx), PASSWORD, pinned_trust(&server));
    wait_event(&h, |e| match e {
        Event::Status(Status::Waking) => panic!("an awake computer must not be woken"),
        Event::Status(Status::Connected { .. }) => Some(()),
        _ => None,
    });
    assert!(rx.recv(&mut [0u8; 200]).is_err(), "no magic packet");
    h.send(Command::Disconnect);
    wait_disconnect(&h);
}

/// A local port whose connection attempts get no answer at all, like a computer that is
/// asleep. Linux silently drops a SYN while the listener's accept queue is full (unless
/// `net.ipv4.tcp_abort_on_overflow` is set), so we fill a backlog-0 queue and never accept.
/// This replaced a TEST-NET address, whose behaviour depended on the developer's router.
struct SilentPort {
    port: u16,
    _listener: socket2::Socket,
    _queued: Vec<std::net::TcpStream>,
}

impl SilentPort {
    fn new() -> Self {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        listener.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
        listener.listen(0).unwrap();
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let mut queued = Vec::new();
        for _ in 0..16 {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Ok(s) => queued.push(s),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Self { port: addr.port(), _listener: listener, _queued: queued };
                }
                Err(e) => panic!("filling the accept queue: {e}"),
            }
        }
        panic!("the accept queue never filled (is net.ipv4.tcp_abort_on_overflow set?)");
    }
}

#[test]
fn wake_on_lan_wakes_a_computer_that_does_not_answer() {
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let asleep = SilentPort::new();
    let h = connect(wake_profile(asleep.port, &rx), PASSWORD, Arc::new(Mutex::new(TrustStore::in_memory())));
    wait_event(&h, |e| matches!(e, Event::Status(Status::Waking)).then_some(()));
    let mut buf = [0u8; 200];
    let n = rx.recv(&mut buf).expect("magic packet");
    assert_eq!(&buf[..n], &bastion_core::wol::magic_packet("00:11:22:33:44:55".parse().unwrap()));
    // Still trying (the computer gets two minutes to start); the user can cancel.
    h.send(Command::Disconnect);
    wait_disconnect(&h);
}

/// Records everything "played" so the test can verify the remote audio stream bit-exactly.
#[derive(Clone, Default)]
struct RecordingHost(Arc<Mutex<Vec<i16>>>);

struct RecordingOut(Arc<Mutex<Vec<i16>>>);

impl bastion_audio::PlaybackDevice for RecordingOut {
    fn write(&mut self, samples: &[i16]) -> anyhow::Result<()> {
        self.0.lock().unwrap().extend_from_slice(samples);
        Ok(())
    }
    fn latency(&self) -> Duration {
        Duration::ZERO
    }
}

impl bastion_audio::AudioHost for RecordingHost {
    fn open_playback(
        &self,
        _device: Option<&str>,
        spec: bastion_audio::PcmSpec,
        _latency: Duration,
    ) -> anyhow::Result<Box<dyn bastion_audio::PlaybackDevice>> {
        assert_eq!(spec, bastion_audio::PcmSpec { rate: 44_100, channels: 2 });
        Ok(Box::new(RecordingOut(self.0.clone())))
    }
    fn open_capture(
        &self,
        _device: Option<&str>,
        _spec: bastion_audio::PcmSpec,
        _fragment: usize,
    ) -> anyhow::Result<Box<dyn bastion_audio::CaptureDevice>> {
        anyhow::bail!("no microphone in this test")
    }
}

#[test]
fn remote_audio_is_played_bit_exact() {
    let server = Server::start();
    let trust = pinned_trust(&server);
    let mut p = profile(server.port);
    p.audio.playback = true;
    let host = RecordingHost::default();
    let h = connect_with_audio(p, PASSWORD, trust, Some(Arc::new(host.clone())));
    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));
    wait_until("server started audio", || server.saw("AUDIO START"));
    // Same ramp the test server generates: 10 chunks x 441 frames, left = v, right = -v.
    let expected: Vec<i16> = (0..10 * 441)
        .flat_map(|i| {
            let v = (i % 30000) as i16;
            [v, -v]
        })
        .collect();
    wait_until("all audio samples played", || host.0.lock().unwrap().len() >= expected.len());
    assert_eq!(&host.0.lock().unwrap()[..expected.len()], &expected[..]);
}

// ───────────────────────── Mock RD Gateway ─────────────────────────
//
// A minimal MS-TSGU HTTP/WebSocket gateway: TLS, HTTP Basic authentication, the
// handshake/tunnel/auth/channel exchange, then data packets relayed to the loopback RDP server.

mod gateway {
    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use futures_util::{SinkExt as _, StreamExt as _};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn packet(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(8 + payload.len());
        p.extend(ty.to_le_bytes());
        p.extend([0, 0]);
        p.extend((8 + payload.len() as u32).to_le_bytes());
        p.extend(payload);
        p
    }

    pub struct Gateway {
        pub port: u16,
        pub fingerprint: String,
        pub log: Arc<Mutex<Vec<String>>>,
        _rt: tokio::runtime::Runtime,
    }

    impl Gateway {
        pub fn saw(&self, s: &str) -> bool {
            self.log.lock().unwrap().iter().any(|l| l == s)
        }
    }

    pub fn start(rdp_port: u16, user: &str, password: &str) -> Gateway {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        let fingerprint = {
            use sha2::Digest as _;
            sha2::Sha256::digest(cert.cert.der()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
        };
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let expected =
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")));
        let l = log.clone();
        rt.spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, expected, log) = (acceptor.clone(), expected.clone(), l.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let (expected, log) = (expected.clone(), log.clone());
                        async move { Ok::<_, std::convert::Infallible>(handle(req, &expected, rdp_port, log)) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .with_upgrades()
                        .await;
                });
            }
        });
        Gateway { port, fingerprint, log, _rt: rt }
    }

    fn handle(
        mut req: Request<hyper::body::Incoming>,
        expected_auth: &str,
        rdp_port: u16,
        log: Arc<Mutex<Vec<String>>>,
    ) -> Response<Empty<Bytes>> {
        log.lock().unwrap().push(format!("HTTP {}", req.method()));
        let auth = req.headers().get(hyper::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
        if auth != expected_auth {
            log.lock().unwrap().push(if auth.is_empty() { "AUTH NONE".into() } else { "AUTH BAD".into() });
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(hyper::header::WWW_AUTHENTICATE, "Basic realm=\"RD Gateway\"")
                .body(Empty::new())
                .unwrap();
        }
        log.lock().unwrap().push("AUTH OK".into());
        let Some(key) = req.headers().get(hyper::header::SEC_WEBSOCKET_KEY).cloned() else {
            return Response::builder().status(StatusCode::BAD_REQUEST).body(Empty::new()).unwrap();
        };
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(&mut req).await {
                let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
                tunnel(ws, rdp_port, log).await;
            }
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(hyper::header::CONNECTION, "Upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::SEC_WEBSOCKET_ACCEPT, accept)
            .body(Empty::new())
            .unwrap()
    }

    async fn tunnel<S>(ws: WebSocketStream<S>, rdp_port: u16, log: Arc<Mutex<Vec<String>>>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                if sink.send(Message::binary(p)).await.is_err() {
                    return;
                }
            }
        });
        let mut buf: Vec<u8> = Vec::new();
        let mut rdp_write: Option<tokio::net::tcp::OwnedWriteHalf> = None;
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Binary(data) = msg else { continue };
            buf.extend_from_slice(&data);
            while buf.len() >= 8 {
                let ty = u16::from_le_bytes([buf[0], buf[1]]);
                let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
                if buf.len() < len {
                    break;
                }
                let pkt: Vec<u8> = buf.drain(..len).collect();
                let payload = &pkt[8..];
                match ty {
                    0x01 => {
                        log.lock().unwrap().push("HANDSHAKE".into());
                        let _ = tx.send(packet(0x02, &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0]));
                    }
                    0x04 => {
                        log.lock().unwrap().push("TUNNEL".into());
                        let _ = tx.send(packet(0x05, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
                    }
                    0x06 => {
                        log.lock().unwrap().push("TUNNEL AUTH".into());
                        let _ = tx.send(packet(0x07, &[0; 8]));
                    }
                    0x08 => {
                        // Channel create: resources are UTF-16 names; record the target host and port.
                        let utf16: Vec<u16> =
                            payload.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        let text = String::from_utf16_lossy(&utf16);
                        log.lock()
                            .unwrap()
                            .push(format!("CHANNEL target_contains_127.0.0.1={}", text.contains("127.0.0.1")));
                        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", rdp_port)).await.unwrap();
                        let (mut r, w) = tcp.into_split();
                        rdp_write = Some(w);
                        let tx2 = tx.clone();
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 16 * 1024];
                            while let Ok(n) = r.read(&mut b).await {
                                if n == 0 {
                                    break;
                                }
                                let mut payload = (n as u16).to_le_bytes().to_vec();
                                payload.extend_from_slice(&b[..n]);
                                if tx2.send(packet(0x0A, &payload)).is_err() {
                                    break;
                                }
                            }
                        });
                        let _ = tx.send(packet(0x09, &[0; 8]));
                    }
                    0x0A => {
                        let n = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                        if let Some(w) = rdp_write.as_mut()
                            && w.write_all(&payload[2..2 + n]).await.is_err()
                        {
                            return;
                        }
                    }
                    other => log.lock().unwrap().push(format!("PACKET {other:#x}")),
                }
            }
        }
    }
}

fn gateway_profile(server: &Server, gw: &gateway::Gateway) -> Profile {
    let mut p = profile(server.port);
    p.gateway = Some(bastion_core::profile::GatewaySettings {
        host: "127.0.0.1".into(),
        port: gw.port,
        same_credentials: true,
        ..Default::default()
    });
    p
}

#[test]
fn connects_through_rd_gateway_with_cert_pinning_and_auth() {
    let server = Server::start();
    let gw = gateway::start(server.port, USER, PASSWORD);
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    let h = connect(gateway_profile(&server, &gw), PASSWORD, trust.clone());

    // 1. The gateway's self-signed certificate is not trusted blindly.
    let rej = wait_event(&h, |e| match e {
        Event::CertificatePrompt(r) => Some(r.clone()),
        _ => None,
    });
    assert_eq!(rej.kind, EndpointKind::Gateway);
    assert_eq!(rej.fingerprint, gw.fingerprint);
    h.send(Command::CertificateDecision { accept: true });

    // 2. Then the RDP host's certificate (end-to-end TLS inside the tunnel).
    let rej = wait_event(&h, |e| match e {
        Event::CertificatePrompt(r) => Some(r.clone()),
        _ => None,
    });
    assert_eq!(rej.kind, EndpointKind::Rdp);
    assert_eq!(rej.fingerprint, server.fingerprint);
    h.send(Command::CertificateDecision { accept: true });

    wait_event(&h, |e| matches!(e, Event::Status(Status::Connected { .. })).then_some(()));
    assert!(gw.saw("AUTH OK"), "gateway credentials must be sent: {:?}", gw.log.lock().unwrap());
    for step in ["HANDSHAKE", "TUNNEL", "TUNNEL AUTH", "CHANNEL target_contains_127.0.0.1=true"] {
        assert!(gw.saw(step), "missing {step}: {:?}", gw.log.lock().unwrap());
    }

    // 3. Desktop and input work through the tunnel.
    wait_until("red desktop via gateway", || centre_pixel(&h).is_some_and(|p| p[0] > 180 && p[1] < 40));
    let mut db = Database::new();
    let a = Scancode::from_u8(false, 0x1E);
    h.send(Command::Input(db.apply([Operation::KeyPressed(a), Operation::KeyReleased(a)])));
    wait_until("key through gateway", || server.saw("KEY DOWN 30 false"));
    assert_eq!(trust.lock().unwrap().entries().count(), 2, "gateway and host pinned separately");

    // Latency through a gateway is measured on the socket to the gateway.
    let link = h.link.sample(&h.frame);
    assert!(link.via_gateway && link.rx_bytes > 0, "{link:?}");
    assert!(link.tcp.is_some(), "gateway socket found by its local address: {link:?}");
}

#[test]
fn wrong_gateway_password_is_reported_clearly() {
    let server = Server::start();
    let gw = gateway::start(server.port, USER, "the-real-password");
    let trust = Arc::new(Mutex::new(TrustStore::in_memory()));
    trust.lock().unwrap().pin(EndpointKind::Gateway, &format!("127.0.0.1:{}", gw.port), &[]).ok();
    let mut p = gateway_profile(&server, &gw);
    p.security.allow_insecure_tls = true; // focus this test on authentication
    let h = connect(p, PASSWORD, trust);
    let (reason, error) = wait_disconnect(&h);
    assert!(error);
    assert!(reason.contains("rejected your credentials"), "{reason}");
    assert!(!reason.contains(".rs:"), "{reason}");
}
