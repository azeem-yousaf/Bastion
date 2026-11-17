//! Wake-on-LAN: the "magic packet" that switches on a sleeping computer, and finding a
//! computer's MAC address in the local neighbour (ARP) table.
//!
//! The packet is a UDP broadcast, so it only reaches computers on the local network (or on a
//! network whose router forwards directed broadcasts).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

pub const DEFAULT_PORT: u16 = 9;
pub const DEFAULT_BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl FromStr for MacAddr {
    type Err = String;

    /// Accepts `00:11:22:33:44:55`, `00-11-22-33-44-55`, `0011.2233.4455` and `001122334455`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: String = s.trim().chars().filter(|c| !matches!(c, ':' | '-' | '.' | ' ')).collect();
        if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("\"{}\" is not a MAC address (expected six pairs like 00:11:22:33:44:55).", s.trim()));
        }
        let mut out = [0u8; 6];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        }
        if out == [0; 6] || out[0] & 1 == 1 {
            return Err(format!("{} is not a computer's MAC address.", MacAddr(out)));
        }
        Ok(Self(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Six `0xFF` bytes followed by the MAC address sixteen times.
pub fn magic_packet(mac: MacAddr) -> [u8; 102] {
    let mut p = [0xFFu8; 102];
    for chunk in p[6..].as_chunks_mut::<6>().0 {
        *chunk = mac.0;
    }
    p
}

/// Where to send the packet: the broadcast address in the profile (empty = all hosts on the
/// local network) and port.
pub fn target(broadcast: &str, port: u16) -> Result<SocketAddr, String> {
    let ip = match broadcast.trim() {
        "" => IpAddr::V4(DEFAULT_BROADCAST),
        s => s.parse::<IpAddr>().map_err(|_| format!("\"{s}\" is not an IP address."))?,
    };
    Ok(SocketAddr::new(ip, if port == 0 { DEFAULT_PORT } else { port }))
}

/// Sends the magic packet for `mac` to `to`.
pub fn send(mac: MacAddr, to: SocketAddr) -> std::io::Result<()> {
    let bind: SocketAddr = if to.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { "[::]:0".parse().unwrap() };
    let socket = UdpSocket::bind(bind)?;
    socket.set_broadcast(true)?;
    socket.send_to(&magic_packet(mac), to)?;
    Ok(())
}

/// Looks up `ip` in a Linux ARP table (`/proc/net/arp` format).
pub fn lookup_arp(table: &str, ip: Ipv4Addr) -> Option<MacAddr> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // IP address, HW type, Flags, HW address, Mask, Device. Flags 0x0 = incomplete entry.
        let (addr, flags, hw) = (cols.first()?, cols.get(2)?, cols.get(3)?);
        (addr.parse::<Ipv4Addr>().ok()? == ip && *flags != "0x0").then(|| hw.parse().ok()).flatten()
    })
}

/// Finds the MAC address of `host` (a name or IPv4 address on the local network), which must be
/// switched on. Blocking: resolves the name and waits briefly for the neighbour table.
pub fn detect_mac(host: &str, rdp_port: u16) -> Result<MacAddr, String> {
    use std::net::ToSocketAddrs;
    let ip = (host.trim(), rdp_port)
        .to_socket_addrs()
        .map_err(|e| format!("Cannot find {}: {e}", host.trim()))?
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{} has no IPv4 address.", host.trim()))?;
    let read = || std::fs::read_to_string("/proc/net/arp").ok().and_then(|t| lookup_arp(&t, ip));
    if let Some(mac) = read() {
        return Ok(mac);
    }
    // Not in the table yet: any packet to it makes the kernel resolve its address.
    if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        let _ = s.send_to(&[0], (ip, DEFAULT_PORT));
    }
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(mac) = read() {
            return Ok(mac);
        }
    }
    Err(format!(
        "Could not find the MAC address of {ip}. The computer must be switched on and on this local network \
         (not reached through a router or gateway)."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    #[test]
    fn parses_common_mac_formats() {
        for s in ["00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455", " 001122334455 "] {
            assert_eq!(s.parse::<MacAddr>(), Ok(MAC), "{s}");
        }
        assert_eq!(MAC.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn rejects_invalid_macs() {
        for s in [
            "",
            "00:11:22:33:44",
            "00:11:22:33:44:55:00",
            "zz:11:22:33:44:55",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(s.parse::<MacAddr>().is_err(), "{s}");
        }
    }

    #[test]
    fn magic_packet_layout() {
        let p = magic_packet(MAC);
        assert_eq!(&p[..6], &[0xFF; 6]);
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &MAC.0);
        }
    }

    #[test]
    fn target_defaults_to_local_broadcast_on_port_9() {
        assert_eq!(target("", 0), Ok("255.255.255.255:9".parse().unwrap()));
        assert_eq!(target(" 192.168.1.255 ", 7), Ok("192.168.1.255:7".parse().unwrap()));
        assert!(target("not-an-ip", 9).is_err());
    }

    #[test]
    fn sends_the_packet_over_udp() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        send(MAC, rx.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 200];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &magic_packet(MAC));
    }

    #[test]
    fn finds_complete_arp_entries_only() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.1      0x1         0x2         00:aa:bb:cc:dd:01     *        enp2s0\n\
                     192.168.1.20    0x1         0x2         00:11:22:33:44:55     *        enp2s0\n\
                     192.168.1.30    0x1         0x0         00:00:00:00:00:00     *        enp2s0\n";
        assert_eq!(lookup_arp(table, "192.168.1.20".parse().unwrap()), Some(MAC));
        assert_eq!(lookup_arp(table, "192.168.1.30".parse().unwrap()), None);
        assert_eq!(lookup_arp(table, "10.0.0.1".parse().unwrap()), None);
    }
}
