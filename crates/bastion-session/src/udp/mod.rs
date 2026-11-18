//! RDP over UDP: the reliable UDP transport (MS-RDPEUDP v1/v2, [`conn`]), TLS on top of it,
//! and the multitransport tunnel (MS-RDPEMT, [`tunnel`]) that carries dynamic-channel PDUs.
//!
//! Windows offers this during connection finalization with an Initiate Multitransport Request.
//! [`UdpTunnel::connect`] performs the UDP handshake, the TLS handshake — accepting only the
//! certificate key already verified on the main TCP connection, so no second trust decision is
//! ever needed — and the tunnel create exchange. Afterwards Soft-Sync moves dynamic channels
//! (graphics, audio, ...) onto the tunnel; the TCP connection keeps input and everything else.
//!
//! Each TLS record is sent in whole datagrams (several small ones may share one), as Windows
//! does; received data is treated as a plain byte stream.

pub mod conn;
pub mod tunnel;
pub mod wire;

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, NamedGroup};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use self::conn::Conn;

/// The whole setup (UDP, TLS and tunnel handshakes) must finish within this; the TCP connection
/// waits for it during connection finalization, so it is kept short.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Worst-case growth of a TLS record over its plaintext: TLS 1.2 AES-GCM adds an 8-byte explicit
/// nonce and a 16-byte tag (TLS 1.3 adds 17 bytes).
const TLS_RECORD_OVERHEAD: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("UDP socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UDP transport closed: {0}")]
    Closed(#[from] conn::Closed),
    #[error("TLS over UDP failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid tunnel data: {0}")]
    Tunnel(#[from] tunnel::Error),
    #[error("the remote computer refused the UDP tunnel (0x{0:08x})")]
    Refused(u32),
    #[error("the remote computer closed the UDP tunnel")]
    PeerClosed,
    #[error("UDP setup timed out")]
    Timeout,
}

/// What the Initiate Multitransport Request and the main connection provide.
#[derive(Debug, Clone)]
pub struct TunnelParams {
    pub peer: SocketAddr,
    pub server_name: String,
    /// The subject public key of the certificate verified on the TCP connection.
    pub server_key: Vec<u8>,
    pub request_id: u32,
    pub cookie: [u8; 16],
}

/// An established tunnel. Dropping it (or its receiving half) closes the UDP connection.
#[derive(Debug)]
pub struct UdpTunnel {
    tx: TunnelTx,
    rx: TunnelRx,
    /// Negotiated RDP-UDP version.
    pub version: u16,
}

impl UdpTunnel {
    pub async fn connect(params: TunnelParams) -> Result<Self, TunnelError> {
        tokio::time::timeout(SETUP_TIMEOUT, setup(params)).await.map_err(|_| TunnelError::Timeout)?
    }

    /// Queues one unframed DRDYNVC PDU. `false` once the tunnel has closed.
    pub fn send(&self, pdu: Vec<u8>) -> bool {
        self.tx.send(pdu)
    }

    /// Next unframed DRDYNVC PDU from the server; `None` once the tunnel has closed (the reason
    /// is logged).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Separate halves, so one task can wait for data while another sends.
    pub fn split(self) -> (TunnelTx, TunnelRx) {
        (self.tx, self.rx)
    }
}

/// Sending half of a [`UdpTunnel`].
#[derive(Debug, Clone)]
pub struct TunnelTx(mpsc::UnboundedSender<Vec<u8>>);

impl TunnelTx {
    /// Queues one unframed DRDYNVC PDU. `false` once the tunnel has closed.
    pub fn send(&self, pdu: Vec<u8>) -> bool {
        self.0.send(pdu).is_ok()
    }
}

/// Receiving half of a [`UdpTunnel`]; dropping it closes the connection.
#[derive(Debug)]
pub struct TunnelRx {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    task: tokio::task::AbortHandle,
}

impl Drop for TunnelRx {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TunnelRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    if crate::tls::crypto_provider().secure_random.fill(&mut b).is_err() {
        // Not security relevant (TLS protects the data); just avoid a fixed value.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        return t.subsec_nanos() ^ std::process::id();
    }
    u32::from_le_bytes(b)
}

async fn setup(p: TunnelParams) -> Result<UdpTunnel, TunnelError> {
    let bind: SocketAddr = if p.peer.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(p.peer).await?;
    let mut conn = Conn::connect(Instant::now(), random_u32());
    let mut buf = vec![0u8; 65536];
    while !conn.is_established() {
        transmit(&socket, &mut conn)?;
        wait(&socket, &mut conn, &mut buf).await?;
    }
    debug!(version = conn.version(), payload = conn.max_payload(), "UDP transport handshake done");

    let config = client_config(&p.server_key, conn.max_payload())?;
    let name =
        ServerName::try_from(p.server_name.clone()).map_err(|_| rustls::Error::General("bad server name".into()))?;
    let tls = rustls::ClientConnection::new(Arc::new(config), name)?;
    let mut link = Link { socket, conn, tls: tls.into(), stream: tunnel::Reassembler::default(), buf };
    while link.tls.is_handshaking() {
        link.flush()?;
        link.wait().await?;
    }
    link.tls.writer().write_all(&tunnel::create_request(p.request_id, &p.cookie))?;
    let first = loop {
        link.flush()?;
        if let Some(pdu) = link.stream.next_pdu()? {
            break pdu;
        }
        link.wait().await?;
    };
    match first.create_response() {
        Some(0) => {}
        Some(hr) => return Err(TunnelError::Refused(hr)),
        None => return Err(TunnelError::Refused(u32::MAX)),
    }
    let version = link.conn.version();
    info!(version, rtt_ms = link.conn.rtt().map(|r| r.as_millis()), "UDP tunnel established");
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(link, out_rx, in_tx)).abort_handle();
    Ok(UdpTunnel { tx: TunnelTx(out_tx), rx: TunnelRx { rx: in_rx, task }, version })
}

/// Sends every datagram that is due. A full socket buffer drops the datagram: the transport
/// retransmits it like any other loss.
fn transmit(socket: &UdpSocket, conn: &mut Conn) -> Result<(), TunnelError> {
    let now = Instant::now();
    while let Some(d) = conn.poll_transmit(now) {
        match socket.try_send(&d) {
            Ok(_) => bastion_metrics::NET_TX.add(d.len() as u64),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    match conn.closed() {
        Some(c) => Err(c.into()),
        None => Ok(()),
    }
}

/// Waits for datagrams (handling every one already queued) or the transport's next timer.
async fn wait(socket: &UdpSocket, conn: &mut Conn, buf: &mut [u8]) -> Result<(), TunnelError> {
    let Some(at) = conn.poll_timeout() else {
        return Err(conn.closed().map_or(TunnelError::PeerClosed, TunnelError::from));
    };
    tokio::select! {
        r = socket.recv(buf) => {
            let n = r?;
            let now = Instant::now();
            conn.handle_datagram(now, &buf[..n]);
            bastion_metrics::NET_RX.add(n as u64);
            while let Ok(n) = socket.try_recv(buf) {
                conn.handle_datagram(now, &buf[..n]);
                bastion_metrics::NET_RX.add(n as u64);
            }
        }
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => {}
    }
    Ok(())
}

/// The transport, TLS and the decrypted tunnel byte stream for one side of a tunnel.
struct Link {
    socket: UdpSocket,
    conn: Conn,
    tls: rustls::Connection,
    stream: tunnel::Reassembler,
    buf: Vec<u8>,
}

impl Link {
    /// Moves TLS output into the transport and sends what is due.
    fn flush(&mut self) -> Result<(), TunnelError> {
        if self.tls.wants_write() {
            let mut out = Vec::new();
            while self.tls.wants_write() {
                self.tls.write_tls(&mut out)?;
            }
            for chunk in record_chunks(&out, self.conn.max_payload()) {
                self.conn.send(chunk);
            }
        }
        transmit(&self.socket, &mut self.conn)
    }

    /// Waits for input or a timer, then decrypts whatever arrived in order.
    async fn wait(&mut self) -> Result<(), TunnelError> {
        wait(&self.socket, &mut self.conn, &mut self.buf).await?;
        while let Some(chunk) = self.conn.recv() {
            let mut rest = &chunk[..];
            while !rest.is_empty() {
                self.tls.read_tls(&mut rest)?;
                self.tls.process_new_packets()?;
            }
        }
        let mut plain = [0u8; 16384];
        loop {
            match self.tls.reader().read(&mut plain) {
                Ok(0) => return Err(TunnelError::PeerClosed),
                Ok(n) => self.stream.push(&plain[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

/// Splits TLS output at record boundaries into chunks of at most `max` bytes, keeping each record
/// in one chunk (records are sized to fit) and packing small ones together.
fn record_chunks(out: &[u8], max: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut cur = Vec::new();
    let mut rest = out;
    while !rest.is_empty() {
        let len = if rest.len() >= 5 { 5 + usize::from(u16::from_be_bytes([rest[3], rest[4]])) } else { rest.len() };
        let (record, tail) = rest.split_at(len.min(rest.len()));
        rest = tail;
        if !cur.is_empty() && cur.len() + record.len() > max {
            chunks.push(std::mem::take(&mut cur));
        }
        if record.len() > max {
            chunks.extend(record.chunks(max).map(<[u8]>::to_vec));
        } else {
            cur.extend_from_slice(record);
        }
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

async fn run(mut link: Link, mut out: mpsc::UnboundedReceiver<Vec<u8>>, inbound: mpsc::UnboundedSender<Vec<u8>>) {
    let mut bw: Option<(Instant, u32)> = None;
    let result: Result<(), TunnelError> = async {
        loop {
            while let Some(pdu) = link.stream.next_pdu()? {
                if pdu.action != tunnel::ACTION_DATA {
                    continue;
                }
                if let Some((_, bytes)) = bw.as_mut() {
                    *bytes = bytes.saturating_add(pdu.payload.len() as u32 + 4);
                }
                for sub in &pdu.subheaders {
                    if let Some(reply) = autodetect(sub, &mut bw) {
                        link.tls.writer().write_all(&tunnel::data(&[], &[&reply])?)?;
                    }
                }
                if !pdu.payload.is_empty() && inbound.send(pdu.payload).is_err() {
                    return Ok(());
                }
            }
            link.flush()?;
            tokio::select! {
                m = out.recv() => {
                    let Some(pdu) = m else { return Ok(()) };
                    link.tls.writer().write_all(&tunnel::data(&pdu, &[])?)?;
                    while let Ok(pdu) = out.try_recv() {
                        link.tls.writer().write_all(&tunnel::data(&pdu, &[])?)?;
                    }
                }
                r = link.wait() => r?,
            }
        }
    }
    .await;
    match result {
        Ok(()) => debug!("UDP tunnel closed"),
        Err(e) => warn!(error = %e, "UDP tunnel failed"),
    }
}

/// Answers the auto-detect requests Windows can put in tunnel subheaders. Only Bandwidth
/// Measure Stop needs a reply: the bytes and time since the matching Start.
fn autodetect(sub: &[u8], bw: &mut Option<(Instant, u32)>) -> Option<Vec<u8>> {
    use ironrdp_pdu::rdp::autodetect::{AutoDetectRequest, AutoDetectResponse, BW_RESULTS_CONTINUOUS};
    if sub.get(1) != Some(&tunnel::SUBHEADER_AUTODETECT_REQUEST) {
        return None;
    }
    match ironrdp_core::decode::<AutoDetectRequest>(sub) {
        Ok(AutoDetectRequest::BandwidthMeasureStart { .. }) => {
            *bw = Some((Instant::now(), 0));
            None
        }
        Ok(AutoDetectRequest::BandwidthMeasureStop { sequence_number, .. }) => {
            let (started, bytes) = bw.take()?;
            let reply = AutoDetectResponse::BandwidthMeasureResults {
                sequence_number,
                response_type: BW_RESULTS_CONTINUOUS,
                time_delta_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
                byte_count: bytes,
            };
            ironrdp_core::encode_vec(&reply).ok()
        }
        Ok(other) => {
            debug!(request = ?other, "UDP tunnel auto-detect request");
            None
        }
        Err(e) => {
            debug!(error = %e, "Undecodable tunnel subheader");
            None
        }
    }
}

fn client_config(server_key: &[u8], max_payload: usize) -> Result<rustls::ClientConfig, rustls::Error> {
    // Classic key exchange only: a post-quantum hybrid share alone is larger than a datagram.
    let mut provider = (*crate::tls::crypto_provider()).clone();
    provider
        .kx_groups
        .retain(|g| matches!(g.name(), NamedGroup::X25519 | NamedGroup::secp256r1 | NamedGroup::secp384r1));
    let provider = Arc::new(provider);
    let verifier = Arc::new(SameKey { key: server_key.to_vec(), provider: provider.clone() });
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.max_fragment_size = Some(max_payload - TLS_RECORD_OVERHEAD);
    Ok(cfg)
}

/// Accepts exactly the key of the certificate verified on the main connection.
#[derive(Debug)]
struct SameKey {
    key: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for SameKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use x509_cert::der::Decode as _;
        let cert = x509_cert::Certificate::from_der(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let key = cert.tbs_certificate().subject_public_key_info().subject_public_key.as_bytes();
        if key == Some(&self.key[..]) {
            Ok(ServerCertVerified::assertion())
        } else {
            warn!("The UDP transport presented a different certificate than the main connection; staying on TCP");
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn records_stay_whole_and_small_ones_share_a_chunk() {
        let rec = |n: usize| {
            let mut r = vec![0x17, 3, 3];
            r.extend_from_slice(&(n as u16).to_be_bytes());
            r.extend(std::iter::repeat_n(0xab, n));
            r
        };
        let mut out = Vec::new();
        for n in [10, 20, 1000, 30] {
            out.extend(rec(n));
        }
        let chunks = record_chunks(&out, 1060);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], [rec(10), rec(20), rec(1000)].concat());
        assert_eq!(chunks[1], rec(30));
        // An oversized record (never produced with max_fragment_size) is still split safely.
        let big = rec(3000);
        assert_eq!(record_chunks(&big, 1060).concat(), big);
    }

    /// A test server built from the same pieces: accepts one client, checks its tunnel create
    /// request and echoes every data PDU back, prefixed with "echo:".
    async fn serve(socket: UdpSocket, cert: rcgen::CertifiedKey, request_id: u32, cookie: [u8; 16]) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = socket.recv_from(&mut buf).await.unwrap();
        socket.connect(from).await.unwrap();
        let conn = Conn::accept(Instant::now(), &buf[..n], 0xfffffff0).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(crate::tls::crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let tls = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut link = Link { socket, conn, tls: tls.into(), stream: tunnel::Reassembler::default(), buf };
        loop {
            while let Some(pdu) = link.stream.next_pdu().unwrap() {
                match pdu.action {
                    tunnel::ACTION_CREATE_REQUEST => {
                        assert_eq!(pdu.payload[..4], request_id.to_le_bytes());
                        let ok = pdu.payload[8..24] == cookie;
                        let hr: u32 = if ok { 0 } else { 0x8000_4005 };
                        let mut resp = vec![tunnel::ACTION_CREATE_RESPONSE, 4, 0, 4];
                        resp.extend_from_slice(&hr.to_le_bytes());
                        link.tls.writer().write_all(&resp).unwrap();
                    }
                    tunnel::ACTION_DATA => {
                        let mut echo = b"echo:".to_vec();
                        echo.extend_from_slice(&pdu.payload);
                        link.tls.writer().write_all(&tunnel::data(&echo, &[]).unwrap()).unwrap();
                    }
                    _ => panic!("unexpected action"),
                }
            }
            if link.flush().is_err() || link.wait().await.is_err() {
                return;
            }
        }
    }

    /// Starts a test tunnel server expecting request ID 7 and `cookie`; returns its address and
    /// the certificate key the client must pin.
    pub(crate) async fn server(cookie: [u8; 16]) -> (SocketAddr, Vec<u8>) {
        crate::tls::install_default_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["pc01".to_owned()]).unwrap();
        let spki = {
            use x509_cert::der::Decode as _;
            let c = x509_cert::Certificate::from_der(cert.cert.der()).unwrap();
            c.tbs_certificate().subject_public_key_info().subject_public_key.as_bytes().unwrap().to_vec()
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(serve(socket, cert, 7, cookie));
        (addr, spki)
    }

    #[tokio::test]
    async fn tunnel_end_to_end_over_localhost() {
        let cookie = [9u8; 16];
        let (peer, server_key) = server(cookie).await;
        let params = TunnelParams { peer, server_name: "pc01".into(), server_key, request_id: 7, cookie };
        let mut t = UdpTunnel::connect(params).await.expect("tunnel");
        assert_eq!(t.version, wire::VERSION_2);
        // Larger than one datagram, so it spans several TLS records and datagrams.
        let big: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        for msg in [b"hello".to_vec(), big.clone(), b"bye".to_vec()] {
            assert!(t.send(msg.clone()));
            let got = tokio::time::timeout(Duration::from_secs(5), t.recv()).await.unwrap().unwrap();
            assert_eq!(got, [b"echo:".to_vec(), msg].concat());
        }
    }

    #[tokio::test]
    async fn a_different_certificate_key_is_refused() {
        let cookie = [1u8; 16];
        let (peer, mut server_key) = server(cookie).await;
        server_key[10] ^= 0xff;
        let params = TunnelParams { peer, server_name: "pc01".into(), server_key, request_id: 7, cookie };
        let err = UdpTunnel::connect(params).await.unwrap_err();
        assert!(matches!(err, TunnelError::Tls(_)), "{err}");
    }

    #[tokio::test]
    async fn a_wrong_cookie_is_refused() {
        let (peer, server_key) = server([1u8; 16]).await;
        let params = TunnelParams { peer, server_name: "pc01".into(), server_key, request_id: 7, cookie: [2u8; 16] };
        let err = UdpTunnel::connect(params).await.unwrap_err();
        assert!(matches!(err, TunnelError::Refused(0x8000_4005)), "{err}");
    }

    #[tokio::test]
    async fn nothing_listening_times_out_quickly() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap(); // bound but never answers
        let params =
            TunnelParams { peer, server_name: "pc01".into(), server_key: vec![], request_id: 1, cookie: [0; 16] };
        let started = Instant::now();
        let err = UdpTunnel::connect(params).await.unwrap_err();
        assert!(matches!(err, TunnelError::Timeout | TunnelError::Closed(conn::Closed::HandshakeTimeout)), "{err}");
        assert!(started.elapsed() <= SETUP_TIMEOUT + Duration::from_secs(1));
        drop(socket);
    }

    #[test]
    fn answers_bandwidth_measure_stop() {
        use ironrdp_pdu::rdp::autodetect::{AutoDetectRequest, AutoDetectResponse};
        let start = ironrdp_core::encode_vec(&AutoDetectRequest::BandwidthMeasureStart {
            sequence_number: 3,
            request_type: ironrdp_pdu::rdp::autodetect::BW_START_RELIABLE_UDP,
        })
        .unwrap();
        let stop = ironrdp_core::encode_vec(&AutoDetectRequest::BandwidthMeasureStop {
            sequence_number: 4,
            request_type: ironrdp_pdu::rdp::autodetect::BW_STOP_RELIABLE_UDP,
            payload: None,
        })
        .unwrap();
        let mut bw = None;
        assert!(autodetect(&start, &mut bw).is_none());
        bw.as_mut().unwrap().1 = 5000;
        let reply = autodetect(&stop, &mut bw).unwrap();
        match ironrdp_core::decode::<AutoDetectResponse>(&reply).unwrap() {
            AutoDetectResponse::BandwidthMeasureResults { sequence_number, byte_count, .. } => {
                assert_eq!((sequence_number, byte_count), (4, 5000));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(reply[1], tunnel::SUBHEADER_AUTODETECT_RESPONSE);
        assert!(bw.is_none());
    }
}
