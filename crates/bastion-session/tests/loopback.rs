//! End-to-end tests: Bastion's real session engine against a local RDP server
//! (`tools/test-server`, built automatically) over TLS + NLA.

use std::io::BufRead as _;
use std::process::{Child, Command as Proc, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bastion_core::profile::Profile;
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

    // User disconnect is a clean, non-error end.
    h.send(Command::Disconnect);
    let (_, error) = wait_disconnect(&h);
    assert!(!error);
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

#[test]
fn unreachable_host_reports_error() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let h = connect(profile(port), PASSWORD, Arc::new(Mutex::new(TrustStore::in_memory())));
    let (reason, error) = wait_disconnect(&h);
    assert!(error && reason.contains("127.0.0.1"), "{reason}");
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
