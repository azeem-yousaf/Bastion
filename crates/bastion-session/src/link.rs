//! Connection quality measurements for one session (shown by the UI's quality indicator).
//!
//! Everything here is cheap to record: byte counters are relaxed atomics bumped next to the
//! existing metrics, and the TCP round-trip time is read from the kernel (`TCP_INFO`) only when
//! the UI samples, about once a second. Through an RD Gateway the TCP socket ends at the
//! gateway, so the remote computer's own measurement (network auto-detect, MS-RDPBCGR 2.2.14)
//! is kept as well when Windows sends one.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Per-session counters, shared between the engine (writer) and the UI (reader).
#[derive(Debug, Default)]
pub struct LinkStats {
    rx: AtomicU64,
    tx: AtomicU64,
    probe: Mutex<Option<TcpProbe>>,
    server: Mutex<Option<ServerReport>>,
    via_gateway: std::sync::atomic::AtomicBool,
    udp: std::sync::atomic::AtomicBool,
}

/// A point-in-time reading; the UI turns two of them into rates.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LinkSample {
    /// Bytes received from / sent to the network (RDP payload, all channels).
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Screen updates published so far (see [`crate::SharedFrame::updates`]).
    pub frames: u64,
    pub tcp: Option<TcpSample>,
    pub server: Option<ServerReport>,
    pub via_gateway: bool,
    /// Graphics and audio travel over the UDP tunnel.
    pub udp: bool,
}

/// The kernel's view of the TCP connection (to the remote computer, or to the gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpSample {
    /// Smoothed round-trip time.
    pub rtt: Duration,
    /// Round-trip time variation (jitter).
    pub rtt_var: Duration,
    /// Segments sent so far, and how many of them had to be retransmitted.
    pub segs_out: u32,
    pub retransmits: u32,
}

/// The remote computer's latest network measurement (Network Characteristics Result).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReport {
    pub at: Instant,
    pub average_rtt_ms: u32,
    pub base_rtt_ms: Option<u32>,
    pub bandwidth_kbps: Option<u32>,
}

impl LinkStats {
    pub fn add_rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Starts measuring a new connection (`None` when its socket cannot be found).
    pub fn set_connection(&self, probe: Option<TcpProbe>, via_gateway: bool) {
        *self.probe.lock().unwrap_or_else(|p| p.into_inner()) = probe;
        *self.server.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.via_gateway.store(via_gateway, Ordering::Relaxed);
        self.udp.store(false, Ordering::Relaxed);
    }

    /// Forgets the connection's socket once it has ended. The probe is a duplicate of that
    /// socket, and the connection only really closes when every duplicate is gone.
    pub fn clear_connection(&self) {
        *self.probe.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Whether the session's UDP tunnel is up.
    pub fn set_udp(&self, on: bool) {
        self.udp.store(on, Ordering::Relaxed);
    }

    pub fn set_server_report(&self, report: ServerReport) {
        *self.server.lock().unwrap_or_else(|p| p.into_inner()) = Some(report);
    }

    pub fn sample(&self, frame: &crate::SharedFrame) -> LinkSample {
        LinkSample {
            rx_bytes: self.rx.load(Ordering::Relaxed),
            tx_bytes: self.tx.load(Ordering::Relaxed),
            frames: frame.updates.load(Ordering::Relaxed),
            tcp: self.probe.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(TcpProbe::read),
            server: *self.server.lock().unwrap_or_else(|p| p.into_inner()),
            via_gateway: self.via_gateway.load(Ordering::Relaxed),
            udp: self.udp.load(Ordering::Relaxed),
        }
    }
}

/// `tcpi_state` of an open connection (`TCP_ESTABLISHED` in `<netinet/tcp.h>`).
const TCP_ESTABLISHED: u8 = 1;

/// A duplicate of a connection's socket descriptor, used only to read `TCP_INFO`.
#[derive(Debug)]
pub struct TcpProbe(OwnedFd);

impl TcpProbe {
    /// Probes a socket we own directly.
    pub fn new(socket: BorrowedFd<'_>) -> Option<Self> {
        let probe = Self(socket.try_clone_to_owned().ok()?);
        probe.read().map(|_| probe)
    }

    /// Finds this process's TCP socket bound to `local` (the gateway client owns its socket
    /// internally and reports only its local address).
    pub fn find_by_local_addr(local: SocketAddr) -> Option<Self> {
        let dir = std::fs::read_dir("/proc/self/fd").ok()?;
        for entry in dir.flatten() {
            let Some(fd) = entry.file_name().to_str().and_then(|n| n.parse::<RawFd>().ok()) else { continue };
            let is_socket = std::fs::read_link(entry.path()).is_ok_and(|t| t.to_string_lossy().starts_with("socket:"));
            if !is_socket || local_addr(fd) != Some(local) {
                continue;
            }
            // SAFETY: `fd` was open a moment ago; duplicating it immediately gives us our own
            // descriptor (at worst for a socket that has just been closed, which reads fail on).
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            return Self::new(borrowed);
        }
        None
    }

    pub fn read(&self) -> Option<TcpSample> {
        // SAFETY: zero is a valid `tcp_info`; the kernel fills at most `len` bytes of it.
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        // SAFETY: valid descriptor, pointer and length for the duration of the call.
        let rc = unsafe {
            libc::getsockopt(
                self.0.as_fd().as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&raw mut info).cast(),
                &raw mut len,
            )
        };
        (rc == 0 && info.tcpi_state == TCP_ESTABLISHED).then(|| TcpSample {
            rtt: Duration::from_micros(u64::from(info.tcpi_rtt)),
            rtt_var: Duration::from_micros(u64::from(info.tcpi_rttvar)),
            segs_out: info.tcpi_segs_out,
            retransmits: info.tcpi_total_retrans,
        })
    }
}

fn local_addr(fd: RawFd) -> Option<SocketAddr> {
    // SAFETY: zero is a valid `sockaddr_storage`; getsockname writes at most `len` bytes.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: valid pointer and length; a stale descriptor just makes the call fail.
    if unsafe { libc::getsockname(fd, (&raw mut storage).cast(), &raw mut len) } != 0 {
        return None;
    }
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says this is a `sockaddr_in`.
            let a: libc::sockaddr_in = unsafe { std::ptr::read((&raw const storage).cast()) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::from((ip, u16::from_be(a.sin_port))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a `sockaddr_in6`.
            let a: libc::sockaddr_in6 = unsafe { std::ptr::read((&raw const storage).cast()) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::from((ip, u16::from_be(a.sin6_port))))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn probe_reads_round_trip_time_and_segments() {
        use std::io::{Read, Write};
        let (mut client, mut server) = pair();
        let probe = TcpProbe::new(client.as_fd()).expect("probe");
        for _ in 0..5 {
            client.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
        }
        let s = probe.read().expect("established");
        assert!(s.segs_out >= 5, "{s:?}");
        assert!(s.rtt < Duration::from_millis(50), "loopback rtt {s:?}");
    }

    #[test]
    fn finds_a_socket_by_its_local_address() {
        let (client, _server) = pair();
        let probe = TcpProbe::find_by_local_addr(client.local_addr().unwrap()).expect("found");
        assert!(probe.read().is_some());
        assert!(TcpProbe::find_by_local_addr("127.0.0.1:1".parse().unwrap()).is_none());
    }

    #[test]
    fn probe_stops_reporting_once_the_connection_closes() {
        let (client, server) = pair();
        let probe = TcpProbe::new(client.as_fd()).unwrap();
        drop(server);
        drop(client);
        // Our duplicate keeps the socket open, but it is no longer established.
        let deadline = Instant::now() + Duration::from_secs(2);
        while probe.read().is_some() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(probe.read().is_none());
    }

    #[test]
    fn clearing_the_connection_lets_the_socket_close() {
        use std::io::Read;
        let (client, mut server) = pair();
        let stats = LinkStats::default();
        stats.set_connection(TcpProbe::new(client.as_fd()), false);
        let frame = crate::SharedFrame::default();
        assert!(stats.sample(&frame).tcp.is_some());
        drop(client);
        // The probe's duplicate still holds the connection open: the peer sees no end of stream.
        server.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 1];
        assert!(server.read(&mut buf).is_err(), "connection closed while the probe was alive");
        stats.clear_connection();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(server.read(&mut buf).unwrap(), 0, "peer must see the connection close");
        assert_eq!(stats.sample(&frame).tcp, None);
    }

    #[test]
    fn sample_combines_counters_frames_and_server_report() {
        let stats = LinkStats::default();
        let frame = crate::SharedFrame::default();
        stats.add_rx(1000);
        stats.add_tx(10);
        frame.updates.fetch_add(3, Ordering::Relaxed);
        let report =
            ServerReport { at: Instant::now(), average_rtt_ms: 12, base_rtt_ms: Some(9), bandwidth_kbps: None };
        stats.set_connection(None, true);
        stats.set_server_report(report);
        let s = stats.sample(&frame);
        assert_eq!((s.rx_bytes, s.tx_bytes, s.frames, s.via_gateway), (1000, 10, 3, true));
        assert_eq!(s.server, Some(report));
        assert_eq!(s.tcp, None);
        // A new connection forgets the old one's report.
        stats.set_connection(None, false);
        assert_eq!(stats.sample(&frame).server, None);
    }
}
