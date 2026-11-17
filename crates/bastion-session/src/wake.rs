//! Connecting to a computer that may be asleep: try briefly, and if it doesn't answer, send
//! Wake-on-LAN packets and keep trying while it boots.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use bastion_core::wol::MacAddr;
use tracing::{debug, info, warn};

/// Timings for [`connect_waking`].
#[derive(Debug, Clone, Copy)]
pub struct WakePlan {
    pub mac: MacAddr,
    pub to: SocketAddr,
    /// How long the first attempt may take before the computer is presumed asleep.
    pub probe: Duration,
    /// Time allowed for each later attempt, and the pause between packets.
    pub retry: Duration,
    /// Give up after this long.
    pub give_up: Duration,
}

impl WakePlan {
    pub fn new(mac: MacAddr, to: SocketAddr) -> Self {
        Self {
            mac,
            to,
            probe: Duration::from_secs(3),
            retry: Duration::from_secs(3),
            give_up: Duration::from_secs(120),
        }
    }
}

#[derive(Debug)]
pub enum WakeError {
    /// The computer answered but refused (it is awake; waking it would not help).
    Refused(std::io::Error),
    /// It never answered.
    NoAnswer { waited: Duration },
}

/// Whether a failed connection attempt looks like a computer that is switched off or asleep
/// (rather than one that is awake and refusing).
pub fn looks_asleep(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(e.kind(), K::TimedOut | K::HostUnreachable | K::NetworkUnreachable)
        || e.raw_os_error().is_some_and(|c| matches!(c, libc::EHOSTDOWN | libc::EHOSTUNREACH | libc::ENETUNREACH))
}

/// Connects with `connect`; if the computer looks asleep, calls `on_waking` once, then sends a
/// magic packet and retries every `plan.retry` until it answers or `plan.give_up` passes.
pub async fn connect_waking<T, F, Fut>(plan: WakePlan, mut connect: F, on_waking: impl FnOnce()) -> Result<T, WakeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let attempt = |limit: Duration, fut: Fut| async move {
        match tokio::time::timeout(limit, fut).await {
            Ok(r) => r,
            Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
        }
    };
    match attempt(plan.probe, connect()).await {
        Ok(s) => return Ok(s),
        Err(e) if !looks_asleep(&e) => return Err(WakeError::Refused(e)),
        Err(e) => debug!(error = %e, "Remote computer not answering; it may be asleep"),
    }
    on_waking();
    info!(mac = %plan.mac, to = %plan.to, "Sending Wake-on-LAN");
    let started = tokio::time::Instant::now();
    loop {
        if let Err(e) = bastion_core::wol::send(plan.mac, plan.to) {
            warn!(error = %e, to = %plan.to, "Could not send the Wake-on-LAN packet");
        }
        let tried = tokio::time::Instant::now();
        match attempt(plan.retry, connect()).await {
            Ok(s) => {
                info!(waited_secs = started.elapsed().as_secs(), "Remote computer woke up");
                return Ok(s);
            }
            // Refused while booting (network up, Remote Desktop not yet): keep waiting.
            Err(e) => debug!(error = %e, "Still waiting for the remote computer"),
        }
        if started.elapsed() >= plan.give_up {
            return Err(WakeError::NoAnswer { waited: started.elapsed() });
        }
        // Failures can be instant; don't spin.
        tokio::time::sleep_until(tried + plan.retry).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const MAC: MacAddr = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    fn receiver() -> (UdpSocket, WakePlan) {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let plan = WakePlan {
            mac: MAC,
            to: rx.local_addr().unwrap(),
            probe: Duration::from_millis(50),
            retry: Duration::from_millis(20),
            give_up: Duration::from_millis(400),
        };
        (rx, plan)
    }

    fn packets(rx: &UdpSocket) -> usize {
        let mut buf = [0u8; 200];
        let mut n = 0;
        while let Ok(len) = rx.recv(&mut buf) {
            assert_eq!(&buf[..len], &bastion_core::wol::magic_packet(MAC));
            n += 1;
        }
        n
    }

    fn unreachable() -> std::io::Error {
        std::io::Error::from_raw_os_error(libc::EHOSTUNREACH)
    }

    #[tokio::test]
    async fn awake_computer_connects_without_waking() {
        let (rx, plan) = receiver();
        let mut waking = false;
        let r = connect_waking(plan, || async { Ok(7) }, || waking = true).await;
        assert_eq!(r.unwrap(), 7);
        assert!(!waking);
        assert_eq!(packets(&rx), 0);
    }

    #[tokio::test]
    async fn refusing_computer_is_not_woken() {
        let (rx, plan) = receiver();
        let r = connect_waking::<(), _, _>(
            plan,
            || async { Err(std::io::ErrorKind::ConnectionRefused.into()) },
            || panic!("must not wake"),
        )
        .await;
        assert!(matches!(r, Err(WakeError::Refused(_))));
        assert_eq!(packets(&rx), 0);
    }

    #[tokio::test]
    async fn sleeping_computer_is_woken_and_connected_once_it_answers() {
        let (rx, plan) = receiver();
        let calls = Arc::new(AtomicU32::new(0));
        let mut waking = 0;
        let c = calls.clone();
        let r = connect_waking(
            plan,
            move || {
                let n = c.fetch_add(1, Ordering::SeqCst);
                async move {
                    match n {
                        0 => std::future::pending().await, // first attempt hangs: asleep
                        1 | 2 => Err(unreachable()),
                        3 => Err(std::io::ErrorKind::ConnectionRefused.into()), // booting
                        _ => Ok("connected"),
                    }
                }
            },
            || waking += 1,
        )
        .await;
        assert_eq!(r.unwrap(), "connected");
        assert_eq!(waking, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(packets(&rx), 4, "one magic packet per retry");
    }

    #[tokio::test]
    async fn gives_up_when_the_computer_never_answers() {
        let (rx, plan) = receiver();
        let r = connect_waking::<(), _, _>(plan, || async { Err(unreachable()) }, || {}).await;
        match r {
            Err(WakeError::NoAnswer { waited }) => assert!(waited >= plan.give_up, "{waited:?}"),
            other => panic!("{other:?}"),
        }
        assert!(packets(&rx) >= 5);
    }

    #[test]
    fn classifies_errors() {
        assert!(looks_asleep(&unreachable()));
        assert!(looks_asleep(&std::io::Error::from_raw_os_error(libc::EHOSTDOWN)));
        assert!(looks_asleep(&std::io::ErrorKind::TimedOut.into()));
        assert!(!looks_asleep(&std::io::ErrorKind::ConnectionRefused.into()));
    }
}
