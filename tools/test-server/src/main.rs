//! Loopback RDP server for Bastion's integration tests.
//!
//! - TLS + NLA (CredSSP) with a fresh self-signed certificate per run
//! - Accepts exactly `--user`/`--password`
//! - Serves a solid-colour 640x480 desktop; pressing the `A` key turns it green,
//!   `B` turns it blue. Every input event is printed to stdout as a line:
//!   `KEY DOWN <code> <ext>`, `KEY UP ...`, `MOUSE MOVE x y`, `MOUSE <button> DOWN|UP`, `WHEEL v`.
//! - Prints `LISTENING <port>` and `CERT_SHA256 <hex>` on startup.

use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use ironrdp_server::tokio::sync::{Mutex, mpsc};
use ironrdp_server::{
    BitmapUpdate, Credentials, DesktopSize, DisplayUpdate, ExactMatchCredentialValidator, KeyboardEvent, MouseEvent,
    PixelFormat, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, TlsIdentityCtx,
};

const W: u16 = 640;

/// Audio test signal: a deterministic ramp so the client side can verify samples bit-exactly.
/// 10 chunks x 441 stereo frames (10 ms each) of 44.1 kHz 16-bit PCM.
pub const AUDIO_CHUNKS: usize = 10;
pub const AUDIO_FRAMES_PER_CHUNK: usize = 441;

fn audio_chunk(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUDIO_FRAMES_PER_CHUNK * 4);
    for f in 0..AUDIO_FRAMES_PER_CHUNK {
        let v = ((n * AUDIO_FRAMES_PER_CHUNK + f) % 30000) as i16;
        out.extend_from_slice(&v.to_le_bytes()); // left
        out.extend_from_slice(&(-v).to_le_bytes()); // right
    }
    out
}

mod sound {
    use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};
    use ironrdp_rdpsnd::server::{NegotiatedFormat, RdpsndError, RdpsndServerHandler, RdpsndServerMessage};
    use ironrdp_server::tokio::sync::mpsc::UnboundedSender;
    use ironrdp_server::{ServerEvent, ServerEventSender, SoundServerFactory};

    #[derive(Default)]
    pub struct Factory {
        sender: Option<UnboundedSender<ServerEvent>>,
    }

    impl ServerEventSender for Factory {
        fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
            self.sender = Some(sender);
        }
    }

    impl SoundServerFactory for Factory {
        fn build_backend(&self) -> Box<dyn RdpsndServerHandler> {
            Box::new(Handler { sender: self.sender.clone(), formats: vec![pcm()] })
        }
    }

    fn pcm() -> AudioFormat {
        AudioFormat {
            format: WaveFormat::PCM,
            n_channels: 2,
            n_samples_per_sec: 44_100,
            n_avg_bytes_per_sec: 44_100 * 4,
            n_block_align: 4,
            bits_per_sample: 16,
            data: None,
        }
    }

    #[derive(Debug)]
    struct Handler {
        sender: Option<UnboundedSender<ServerEvent>>,
        formats: Vec<AudioFormat>,
    }

    impl RdpsndServerHandler for Handler {
        fn get_formats(&self) -> &[AudioFormat] {
            &self.formats
        }

        fn choose_format<'a>(&mut self, common: &'a [NegotiatedFormat]) -> Option<&'a NegotiatedFormat> {
            common.first()
        }

        fn start(&mut self, _format: &NegotiatedFormat) -> Result<(), Box<dyn RdpsndError>> {
            println!("AUDIO START");
            let Some(tx) = self.sender.clone() else { return Ok(()) };
            ironrdp_server::tokio::spawn(async move {
                for n in 0..super::AUDIO_CHUNKS {
                    let ts = (n * 10) as u32;
                    if tx.send(ServerEvent::Rdpsnd(RdpsndServerMessage::Wave(super::audio_chunk(n), ts))).is_err() {
                        return;
                    }
                    ironrdp_server::tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                println!("AUDIO SENT");
            });
            Ok(())
        }

        fn stop(&mut self) {}
    }
}
const H: u16 = 480;

fn solid(rgb: [u8; 3]) -> BitmapUpdate {
    let stride = usize::from(W) * 4;
    let mut data = Vec::with_capacity(stride * usize::from(H));
    for _ in 0..usize::from(W) * usize::from(H) {
        // BgrA32 byte order.
        data.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0xFF]);
    }
    BitmapUpdate {
        x: 0,
        y: 0,
        width: NonZeroU16::new(W).unwrap(),
        height: NonZeroU16::new(H).unwrap(),
        format: PixelFormat::BgrA32,
        data: data.into(),
        stride: NonZeroUsize::new(stride).unwrap(),
    }
}

struct Input {
    colour_tx: mpsc::UnboundedSender<[u8; 3]>,
}

impl RdpServerInputHandler for Input {
    fn keyboard(&mut self, event: KeyboardEvent) {
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                println!("KEY DOWN {code} {extended}");
                match code {
                    0x1E => drop(self.colour_tx.send([0, 200, 0])),
                    0x30 => drop(self.colour_tx.send([0, 0, 200])),
                    _ => {}
                }
            }
            KeyboardEvent::Released { code, extended } => println!("KEY UP {code} {extended}"),
            KeyboardEvent::UnicodePressed(c) => println!("UNICODE DOWN {c}"),
            KeyboardEvent::UnicodeReleased(c) => println!("UNICODE UP {c}"),
            KeyboardEvent::Synchronize(f) => println!("SYNC {}", f.bits()),
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        let line = match event {
            MouseEvent::Move { x, y } => format!("MOUSE MOVE {x} {y}"),
            MouseEvent::LeftPressed => "MOUSE LEFT DOWN".into(),
            MouseEvent::LeftReleased => "MOUSE LEFT UP".into(),
            MouseEvent::RightPressed => "MOUSE RIGHT DOWN".into(),
            MouseEvent::RightReleased => "MOUSE RIGHT UP".into(),
            MouseEvent::MiddlePressed => "MOUSE MIDDLE DOWN".into(),
            MouseEvent::MiddleReleased => "MOUSE MIDDLE UP".into(),
            MouseEvent::VerticalScroll { value } => format!("WHEEL {value}"),
            other => format!("MOUSE OTHER {other:?}"),
        };
        println!("{line}");
    }
}

struct Display {
    colour_rx: Arc<Mutex<mpsc::UnboundedReceiver<[u8; 3]>>>,
}

struct Updates {
    first: bool,
    colour_rx: Arc<Mutex<mpsc::UnboundedReceiver<[u8; 3]>>>,
}

#[async_trait::async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: W, height: H }
    }

    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Updates { first: true, colour_rx: self.colour_rx.clone() }))
    }
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>> {
        if std::mem::take(&mut self.first) {
            return Ok(Some(DisplayUpdate::Bitmap(solid([200, 0, 0]))));
        }
        // Cancel-safe: `recv` on a locked receiver loses nothing if dropped.
        let colour = self.colour_rx.lock().await.recv().await;
        Ok(colour.map(|c| DisplayUpdate::Bitmap(solid(c))))
    }
}

fn arg(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| default.to_owned())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TEST_SERVER_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let user = arg("--user", "tester");
    let password = arg("--password", "Passw0rd!");
    let port: u16 = arg("--port", "0").parse()?;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let dir = std::env::temp_dir().join(format!("bastion-test-server-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    let identity = TlsIdentityCtx::init_from_paths(&cert_path, &key_path)?;
    let acceptor = identity.make_acceptor()?;

    let listener = std::net::TcpListener::bind(("127.0.0.1", port))?;
    let addr = listener.local_addr()?;
    drop(listener); // RdpServer binds itself; the port stays free long enough on loopback.

    let fp: String = {
        use sha2::Digest as _;
        sha2::Sha256::digest(cert.cert.der()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    };

    let (colour_tx, colour_rx) = mpsc::unbounded_channel();
    let mut server = RdpServer::builder()
        .with_addr(addr)
        .with_hybrid(acceptor, identity.pub_key.clone())
        .with_input_handler(Input { colour_tx })
        .with_display_handler(Display { colour_rx: Arc::new(Mutex::new(colour_rx)) })
        .with_sound_factory(Some(Box::new(sound::Factory::default())))
        .build();
    let creds = Credentials { username: user, password, domain: None };
    // CredSSP/NLA verifies NTLM against pre-loaded credentials; the validator covers TLS-only logons.
    server.set_credentials(Some(creds.clone()));
    server.set_credential_validator(Some(Arc::new(ExactMatchCredentialValidator::new(creds))));

    println!("LISTENING {}", addr.port());
    println!("CERT_SHA256 {fp}");
    use std::io::Write as _;
    std::io::stdout().flush()?;
    server.run().await.context("server run")
}
