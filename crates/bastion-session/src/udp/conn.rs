//! MS-RDPEUDP reliable mode (RDP-UDP-R), versions 1 and 2, as a state machine without I/O.
//!
//! The caller feeds received datagrams to [`Conn::handle_datagram`], sends whatever
//! [`Conn::poll_transmit`] returns, and calls `poll_transmit` again at [`Conn::poll_timeout`].
//! Data handed to [`Conn::send`] (at most [`Conn::max_payload`] bytes per call) arrives in order
//! through [`Conn::recv`] on the other side.
//!
//! - Acknowledgements are ACK vectors (run-length encoded received / not-received states) that
//!   end at the highest Source sequence number seen, so the sender recovers their start from
//!   their length. They start after the peer's ACK-of-ACKs reset point.
//! - Losses (three later packets acknowledged) are retransmitted at once; anything else after the
//!   retransmit time-out, doubling each time. Five retransmits without an answer close the
//!   connection, as do 65 s without hearing from the peer.
//! - Congestion control is NewReno-like, in packets: slow start, halving at most once per round
//!   trip on loss or a congestion notification (CN), answered with CWR.
//!
//! [`Conn::accept`] plays the server side; Bastion only uses it in tests.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::wire::{self, Outgoing, Payload, Run, STATE_NOT_RECEIVED, STATE_RECEIVED, Syn, seq_before};

/// Datagrams we can buffer (advertised `uReceiveWindowSize`).
pub const RECEIVE_WINDOW: u16 = 1024;
/// Our MTU advertisement: the largest allowed.
const MTU: u16 = wire::MTU_MAX;
/// SYN / SYN+ACK: sent four times, 800 ms apart (MS-RDPEUDP product note <7>).
const SYN_INTERVAL: Duration = Duration::from_millis(800);
const SYN_ATTEMPTS: u32 = 4;
/// Retransmits of one datagram before giving up (product note <9>).
const MAX_RETRANSMITS: u32 = 5;
const MAX_RTO: Duration = Duration::from_secs(16);
/// The peer is gone after this long without a datagram (3.1.1.9).
const IDLE_TIMEOUT: Duration = Duration::from_secs(65);
/// Windows sends four keepalives per 65 s when quiet; do the same.
const KEEPALIVE: Duration = Duration::from_secs(15);
/// Acknowledge every second Source Packet (product note <4>).
const ACK_EVERY: u32 = 2;
/// Send an ACK-of-ACKs reset point this often (2.2.2.6).
const ACK_OF_ACKS_EVERY: u32 = 20;
/// ACK vector elements carried by a data datagram; space for them is reserved in every one.
const DATA_ACK_RUNS: usize = 32;
/// ACK vector elements in an acknowledgement-only datagram.
const MAX_ACK_RUNS: usize = 256;
/// How far behind the delivery point the ACK vector still reports received packets when the
/// peer sends no ACK-of-ACKs.
const ACK_HISTORY: u32 = 1024;
const MAX_CWND: f64 = RECEIVE_WINDOW as f64;
const INITIAL_CWND: f64 = 10.0;
/// Acknowledgements kept for [`Conn::diagnostics`].
const RECENT_ACKS: usize = 8;
/// Never shrink below this: with fewer packets in flight, three later acknowledgements can't
/// arrive and every loss would wait for the retransmit time-out.
const MIN_CWND: f64 = 4.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Closed {
    #[error("the remote computer did not answer the UDP handshake")]
    HandshakeTimeout,
    #[error("data was not acknowledged after {MAX_RETRANSMITS} retransmits")]
    RetransmitLimit,
    #[error("nothing received for {} seconds", IDLE_TIMEOUT.as_secs())]
    IdleTimeout,
}

#[derive(Debug)]
enum State {
    /// Client: SYN sent, waiting for SYN+ACK.
    SynSent {
        attempts: u32,
        next: Instant,
    },
    /// Server: SYN+ACK sent, waiting for the client's ACK.
    SynReceived {
        attempts: u32,
        next: Instant,
    },
    Established,
    Closed(Closed),
}

#[derive(Debug)]
struct InFlight {
    source: u32,
    data: Vec<u8>,
    sent_at: Instant,
    deadline: Instant,
    retransmits: u32,
    acked: bool,
    /// Marked lost from the peer's ACK vector and not resent since.
    resend: bool,
}

/// Counters for logs and diagnostics.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    /// Retransmits after three later packets were acknowledged.
    pub fast_retransmits: u64,
    /// Retransmits after the retransmit time-out.
    pub timeout_retransmits: u64,
    /// Received Source Packets that were already received.
    pub duplicates: u64,
}

#[derive(Debug)]
pub struct Conn {
    state: State,
    local: Syn,
    peer_isn: u32,
    version: u16,
    /// Largest datagram we may send.
    datagram_limit: usize,
    last_rx: Instant,
    last_tx: Instant,
    out: VecDeque<Vec<u8>>,

    // Sender.
    next_coded: u32,
    next_source: u32,
    pending: VecDeque<Vec<u8>>,
    in_flight: VecDeque<InFlight>,
    peer_window: u16,
    cwnd: f64,
    ssthresh: f64,
    srtt: Option<Duration>,
    last_reaction: Option<Instant>,
    cwr_pending: bool,
    /// Source sequence number that carried our last CWR: older CNs are ignored.
    cwr_seq: Option<u32>,
    since_ack_of_acks: u32,
    stats: Stats,
    /// The peer's latest acknowledgements (snSourceAck, flags, vector), for failure reports.
    recent_acks: VecDeque<(u32, u16, Vec<Run>)>,

    // Receiver.
    /// The ACK vector covers `floor + 1 ..= floor + got.len()`.
    floor: u32,
    got: VecDeque<bool>,
    next_deliver: u32,
    started: bool,
    buffered: HashMap<u32, Vec<u8>>,
    delivered: VecDeque<Vec<u8>>,
    unacked: u32,
    ack_now: bool,
    ack_deadline: Option<Instant>,
    /// The pending acknowledgement was held back by the delayed-ACK timer.
    ack_delayed: bool,
    /// Loss seen and reported with CN until the peer answers with CWR.
    cn: bool,
    /// Gaps at or before this sequence number were already reported.
    cn_reported: Option<u32>,
}

impl Conn {
    fn new(now: Instant, local: Syn, state: State) -> Self {
        Self {
            state,
            local,
            peer_isn: 0,
            version: wire::VERSION_1,
            datagram_limit: usize::from(wire::MTU_MIN),
            last_rx: now,
            last_tx: now,
            out: VecDeque::new(),
            next_coded: local.initial_seq.wrapping_add(1),
            next_source: local.initial_seq.wrapping_add(1),
            pending: VecDeque::new(),
            in_flight: VecDeque::new(),
            peer_window: 64,
            cwnd: INITIAL_CWND,
            ssthresh: MAX_CWND,
            srtt: None,
            last_reaction: None,
            cwr_pending: false,
            cwr_seq: None,
            since_ack_of_acks: 0,
            stats: Stats::default(),
            recent_acks: VecDeque::new(),
            floor: 0,
            got: VecDeque::new(),
            next_deliver: 0,
            started: false,
            buffered: HashMap::new(),
            delivered: VecDeque::new(),
            unacked: 0,
            ack_now: false,
            ack_deadline: None,
            ack_delayed: false,
            cn: false,
            cn_reported: None,
        }
    }

    /// Starts a client connection: the first [`Self::poll_transmit`] returns the SYN.
    pub fn connect(now: Instant, initial_seq: u32) -> Self {
        let local = Syn { initial_seq, up_mtu: MTU, down_mtu: MTU, version: Some(wire::VERSION_2) };
        let mut c = Self::new(now, local, State::SynSent { attempts: 1, next: now + SYN_INTERVAL });
        c.out.push_back(wire::encode_syn(local, RECEIVE_WINDOW, None, usize::from(MTU)));
        c
    }

    /// Answers a client's SYN (server side, for tests). `None` if `syn` is not a SYN.
    pub fn accept(now: Instant, syn: &[u8], initial_seq: u32) -> Option<Self> {
        let d = wire::decode(syn).ok()?;
        let peer = d.syn.filter(|_| d.flags & wire::FLAG_ACK == 0)?;
        let version = peer.version.map(|v| v.min(wire::VERSION_2));
        let local = Syn { initial_seq, up_mtu: MTU.min(peer.down_mtu), down_mtu: MTU.min(peer.up_mtu), version };
        let mut c = Self::new(now, local, State::SynReceived { attempts: 1, next: now + SYN_INTERVAL });
        c.on_peer_syn(peer, d.receive_window);
        c.out.push_back(c.syn_ack());
        Some(c)
    }

    fn syn_ack(&self) -> Vec<u8> {
        let pad = usize::from(self.local.up_mtu.min(self.local.down_mtu));
        wire::encode_syn(self.local, RECEIVE_WINDOW, Some(self.peer_isn), pad)
    }

    fn on_peer_syn(&mut self, peer: Syn, window: u16) {
        self.peer_isn = peer.initial_seq;
        self.version = match (self.local.version, peer.version) {
            (Some(a), Some(b)) => a.min(b).min(wire::VERSION_2),
            _ => wire::VERSION_1,
        };
        self.datagram_limit = usize::from(self.local.up_mtu.min(peer.down_mtu).max(wire::MTU_MIN));
        self.peer_window = window.max(1);
        // Data starts at ISN + 1 (3.1.5.1.4); `on_source` also accepts ISN itself (3.1.1).
        self.floor = peer.initial_seq;
        self.next_deliver = peer.initial_seq.wrapping_add(1);
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    pub fn closed(&self) -> Option<Closed> {
        match self.state {
            State::Closed(c) => Some(c),
            _ => None,
        }
    }

    /// Negotiated RDP-UDP version (1 or 2).
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// One line describing the sender's state and the peer's latest acknowledgements, logged
    /// when the connection fails (never per packet).
    pub fn diagnostics(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!(
            "local_isn={} peer_isn={} version={} next_source={} oldest_unacked={:?} in_flight={} cwnd={:.1} peer_window={} \
             rtt={:?} highest_received={} next_deliver={} {:?}; recent acks (snSourceAck flags [state:len]):",
            self.local.initial_seq,
            self.peer_isn,
            self.version,
            self.next_source,
            self.in_flight.iter().find(|f| !f.acked).map(|f| (f.source, f.retransmits)),
            self.in_flight.len(),
            self.cwnd,
            self.peer_window,
            self.srtt,
            self.highest(),
            self.next_deliver,
            self.stats,
        );
        for (ack, flags, runs) in &self.recent_acks {
            let _ = write!(s, " {ack} {flags:#06x} [");
            for r in runs {
                let _ = write!(s, "{}:{} ", r.state, r.len);
            }
            s.push(']');
        }
        s
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Largest chunk [`Self::send`] accepts (valid once established).
    pub fn max_payload(&self) -> usize {
        self.datagram_limit - wire::data_headers_len(DATA_ACK_RUNS, true)
    }

    /// Bytes queued or not yet acknowledged.
    pub fn queued(&self) -> usize {
        self.pending.iter().map(Vec::len).sum::<usize>() + self.in_flight.iter().map(|f| f.data.len()).sum::<usize>()
    }

    /// Queues one chunk for reliable, in-order delivery.
    pub fn send(&mut self, data: Vec<u8>) {
        debug_assert!(data.len() <= self.max_payload());
        if self.closed().is_none() {
            self.pending.push_back(data);
        }
    }

    /// Next chunk received in order.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }

    fn min_rto(&self) -> Duration {
        if self.version >= wire::VERSION_2 { Duration::from_millis(300) } else { Duration::from_millis(500) }
    }

    fn rto(&self) -> Duration {
        self.srtt.map_or(self.min_rto(), |r| (r * 2).max(self.min_rto()))
    }

    fn delayed_ack(&self) -> Duration {
        if self.version >= wire::VERSION_2 {
            self.srtt.map_or(Duration::from_millis(50), |r| {
                (r / 2).clamp(Duration::from_millis(50), Duration::from_millis(200))
            })
        } else {
            Duration::from_millis(200)
        }
    }

    fn close(&mut self, why: Closed) {
        if self.closed().is_none() {
            self.state = State::Closed(why);
            self.pending.clear();
            self.in_flight.clear();
            self.out.clear();
        }
    }

    /// When [`Self::poll_transmit`] should run next.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if !self.out.is_empty() {
            return Some(self.last_tx.min(self.last_rx));
        }
        let mut t = match self.state {
            State::Closed(_) => return None,
            State::SynSent { next, .. } | State::SynReceived { next, .. } => next,
            State::Established => self.last_tx + KEEPALIVE,
        };
        t = t.min(self.last_rx + IDLE_TIMEOUT);
        if let Some(d) = self.ack_deadline {
            t = t.min(d);
        }
        if let Some(f) = self.in_flight.iter().filter(|f| !f.acked).map(|f| f.deadline).min() {
            t = t.min(f);
        }
        Some(t)
    }

    #[cfg(test)]
    fn debug_state(&self) -> String {
        format!(
            "{:?} state={:?} pending={} in_flight={} (acked {}, resend {}, max retransmits {}) cwnd={:.1} peer_window={} \
             floor={} highest={} next_deliver={} buffered={} delivered={}",
            self.stats,
            self.state,
            self.pending.len(),
            self.in_flight.len(),
            self.in_flight.iter().filter(|f| f.acked).count(),
            self.in_flight.iter().filter(|f| f.resend).count(),
            self.in_flight.iter().map(|f| f.retransmits).max().unwrap_or(0),
            self.cwnd,
            self.peer_window,
            self.floor,
            self.highest(),
            self.next_deliver,
            self.buffered.len(),
            self.delivered.len(),
        )
    }

    // ---------------------------------------------------------------- receiving

    /// Processes one received datagram. Malformed or unexpected datagrams are ignored.
    pub fn handle_datagram(&mut self, now: Instant, buf: &[u8]) {
        let Ok(d) = wire::decode(buf) else { return };
        if self.closed().is_some() {
            return;
        }
        match self.state {
            State::SynSent { .. } => {
                let Some(peer) = d.syn else { return };
                if d.flags & wire::FLAG_ACK == 0 || d.source_ack != self.local.initial_seq {
                    return;
                }
                self.on_peer_syn(peer, d.receive_window);
                self.state = State::Established;
                self.last_rx = now;
                self.ack_now = true;
                return;
            }
            State::SynReceived { .. } => {
                if d.syn.is_some() {
                    // The client did not get our SYN+ACK: answer its repeated SYN.
                    self.out.push_back(self.syn_ack());
                    return;
                }
                if d.flags & wire::FLAG_ACK == 0 {
                    return;
                }
                self.state = State::Established;
            }
            State::Established => {
                if d.syn.is_some() {
                    // A repeated SYN+ACK (or SYN): our ACK was lost.
                    self.ack_now = true;
                    self.last_rx = now;
                    return;
                }
            }
            State::Closed(_) => return,
        }
        self.last_rx = now;
        self.peer_window = d.receive_window.max(1);
        if d.flags & wire::FLAG_CWR != 0 {
            self.cn = false;
        }
        if let Some(runs) = &d.ack_vector {
            self.on_ack(now, d.source_ack, runs, d.flags);
        }
        match d.payload {
            Some(Payload::Source { source, .. }) => {
                if let Some(reset) = d.ack_of_acks {
                    self.on_ack_of_acks(reset);
                }
                self.on_source(now, source, d.data);
            }
            // FEC Packets are optional to use and never acknowledged; lost data is resent anyway.
            Some(Payload::Fec { .. }) => {}
            None => {
                if let Some(reset) = d.ack_of_acks {
                    self.on_ack_of_acks(reset);
                }
            }
        }
    }

    fn on_ack_of_acks(&mut self, reset: u32) {
        // Never past what we have delivered: the vector must keep covering the gaps.
        let limit = self.next_deliver.wrapping_sub(1);
        let reset = if seq_before(limit, reset) { limit } else { reset };
        self.advance_floor(reset);
    }

    fn advance_floor(&mut self, to: u32) {
        if !seq_before(self.floor, to) {
            return;
        }
        let n = to.wrapping_sub(self.floor) as usize;
        if n >= self.got.len() {
            self.got.clear();
        } else {
            self.got.drain(..n);
        }
        self.floor = to;
    }

    fn highest(&self) -> u32 {
        self.floor.wrapping_add(self.got.len() as u32)
    }

    fn on_source(&mut self, now: Instant, seq: u32, data: &[u8]) {
        if !self.started && seq == self.peer_isn && self.next_deliver == self.peer_isn.wrapping_add(1) {
            // The peer numbers its first Source Packet ISN rather than ISN + 1.
            self.floor = self.peer_isn.wrapping_sub(1);
            self.got.clear();
            self.next_deliver = self.peer_isn;
        }
        self.started = true;
        let offset = seq.wrapping_sub(self.next_deliver);
        if offset >= u32::from(RECEIVE_WINDOW) {
            // Already delivered (a duplicate: acknowledge again at once) or beyond our window.
            if seq_before(seq, self.next_deliver) {
                self.ack_now = true;
            }
            return;
        }
        let idx = seq.wrapping_sub(self.floor).wrapping_sub(1) as usize;
        if idx < self.got.len() && self.got[idx] {
            self.stats.duplicates += 1;
            self.push_ack();
            return;
        }
        self.stats.received += 1;
        let in_order = idx == self.got.len() && seq == self.next_deliver;
        if idx >= self.got.len() {
            self.got.resize(idx + 1, false);
        }
        self.got[idx] = true;
        if seq == self.next_deliver {
            self.delivered.push_back(data.to_vec());
            self.next_deliver = self.next_deliver.wrapping_add(1);
            while let Some(d) = self.buffered.remove(&self.next_deliver) {
                self.delivered.push_back(d);
                self.next_deliver = self.next_deliver.wrapping_add(1);
            }
        } else {
            self.buffered.insert(seq, data.to_vec());
        }
        // Keep the vector bounded when the peer sends no ACK-of-ACKs.
        let keep_from = self.next_deliver.wrapping_sub(1).wrapping_sub(ACK_HISTORY);
        self.advance_floor(keep_from);
        self.detect_gap();
        self.unacked += 1;
        if !in_order || !self.buffered.is_empty() || self.unacked >= ACK_EVERY {
            // Queued now, not at the end of the batch: a burst read in one go still gets an
            // acknowledgement per two packets, so losing one of them costs nothing.
            self.push_ack();
        } else if self.ack_deadline.is_none() {
            self.ack_deadline = Some(now + self.delayed_ack());
        }
    }

    /// A datagram counts as lost once three later ones arrived (3.1.1.4.1): report it with CN.
    fn detect_gap(&mut self) {
        let first = self.next_deliver.wrapping_sub(self.floor).wrapping_sub(1) as usize;
        let Some(gap) = (first..self.got.len()).find(|&i| !self.got[i]) else { return };
        let gap_seq = self.floor.wrapping_add(gap as u32 + 1);
        if self.cn_reported.is_some_and(|r| !seq_before(r, gap_seq)) {
            return;
        }
        if self.got.iter().skip(gap + 1).filter(|&&g| g).count() >= 3 {
            self.cn = true;
            self.cn_reported = Some(gap_seq);
        }
    }

    /// The ACK vector for `floor + 1 ..= highest`, keeping at most `max` of the newest runs.
    fn ack_runs(&self, max: usize) -> Vec<Run> {
        let mut runs: Vec<Run> = Vec::new();
        for &g in &self.got {
            let state = if g { STATE_RECEIVED } else { STATE_NOT_RECEIVED };
            match runs.last_mut() {
                Some(r) if r.state == state && r.len < wire::MAX_RUN => r.len += 1,
                _ => runs.push(Run { state, len: 1 }),
            }
        }
        if runs.len() > max {
            runs.drain(..runs.len() - max);
        }
        runs
    }

    fn on_ack(&mut self, now: Instant, highest: u32, runs: &[Run], flags: u16) {
        if self.recent_acks.len() == RECENT_ACKS {
            self.recent_acks.pop_front();
        }
        self.recent_acks.push_back((highest, flags, runs.to_vec()));
        let total: u32 = runs.iter().map(|r| u32::from(r.len)).sum();
        // Only acknowledgements of something we sent count (5.1.1).
        if total > 0 && seq_before(highest, self.next_source) {
            let mut seq = highest.wrapping_sub(total).wrapping_add(1);
            let mut newly = 0u32;
            let mut sample = None;
            for r in runs {
                for _ in 0..r.len {
                    if r.state == STATE_RECEIVED
                        && let Some(f) = self.in_flight.iter_mut().find(|f| f.source == seq)
                        && !f.acked
                    {
                        f.acked = true;
                        newly += 1;
                        if seq == highest && f.retransmits == 0 && flags & wire::FLAG_ACKDELAYED == 0 {
                            sample = Some(now.saturating_duration_since(f.sent_at));
                        }
                    }
                    seq = seq.wrapping_add(1);
                }
            }
            if let Some(s) = sample {
                self.srtt = Some(self.srtt.map_or(s, |r| (r * 7 + s) / 8));
            }
            for _ in 0..newly {
                self.cwnd = if self.cwnd < self.ssthresh { self.cwnd + 1.0 } else { self.cwnd + 1.0 / self.cwnd };
            }
            self.cwnd = self.cwnd.min(MAX_CWND);
            // Lost: not acknowledged while three later ones were. Each packet gets one fast
            // retransmit; if that copy is lost too, the retransmit time-out takes over (as in TCP).
            // Re-sending on every acknowledgement would use up the retransmit limit within a few
            // round trips on a fast LAN.
            let mut later = 0;
            let mut lost = false;
            for f in self.in_flight.iter_mut().rev() {
                if f.acked {
                    later += 1;
                } else if later >= 3 && !f.resend && f.retransmits == 0 && seq_before(f.source, highest) {
                    f.resend = true;
                    lost = true;
                    self.stats.fast_retransmits += 1;
                }
            }
            if lost {
                self.congestion(now);
            }
            while self.in_flight.front().is_some_and(|f| f.acked) {
                self.in_flight.pop_front();
            }
        }
        if flags & wire::FLAG_CN != 0 && !self.cwr_seq.is_some_and(|c| seq_before(highest, c)) {
            self.congestion(now);
        }
    }

    /// Halve the window, at most once per round trip (3.1.1.8).
    fn congestion(&mut self, now: Instant) {
        let rtt = self.srtt.unwrap_or(self.min_rto());
        if self.last_reaction.is_some_and(|t| now.saturating_duration_since(t) < rtt) {
            return;
        }
        self.ssthresh = (self.cwnd / 2.0).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        self.cwr_pending = true;
        self.last_reaction = Some(now);
    }

    // ---------------------------------------------------------------- sending

    /// The next datagram to send, after running any due timers.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            self.on_timers(now);
            if self.is_established() {
                self.fill(now);
            }
        }
        let d = self.out.pop_front()?;
        self.last_tx = now;
        Some(d)
    }

    fn on_timers(&mut self, now: Instant) {
        match self.state {
            State::Closed(_) => return,
            State::SynSent { attempts, next } | State::SynReceived { attempts, next } if now >= next => {
                if attempts >= SYN_ATTEMPTS {
                    self.close(Closed::HandshakeTimeout);
                    return;
                }
                let d = match self.state {
                    State::SynSent { .. } => wire::encode_syn(self.local, RECEIVE_WINDOW, None, usize::from(MTU)),
                    _ => self.syn_ack(),
                };
                self.out.push_back(d);
                let next = now + SYN_INTERVAL;
                self.state = match self.state {
                    State::SynSent { .. } => State::SynSent { attempts: attempts + 1, next },
                    _ => State::SynReceived { attempts: attempts + 1, next },
                };
                return;
            }
            _ => {}
        }
        if now.saturating_duration_since(self.last_rx) >= IDLE_TIMEOUT {
            self.close(Closed::IdleTimeout);
            return;
        }
        if self.ack_deadline.is_some_and(|d| now >= d) {
            self.ack_deadline = None;
            self.ack_now = true;
            self.ack_delayed = true;
        }
        let rto = self.rto();
        let mut timed_out = false;
        let mut gave_up = false;
        for f in self.in_flight.iter_mut().filter(|f| !f.acked && now >= f.deadline) {
            if f.retransmits >= MAX_RETRANSMITS {
                gave_up = true;
                break;
            }
            if !f.resend {
                self.stats.timeout_retransmits += 1;
            }
            f.resend = true;
            timed_out = true;
            // Doubles per retransmit (product note <10>).
            f.deadline = now + (rto * 2u32.saturating_pow(f.retransmits + 1)).min(MAX_RTO);
        }
        if gave_up {
            self.close(Closed::RetransmitLimit);
            return;
        }
        if timed_out {
            // A time-out is a loss too: react and tell the peer with CWR (3.1.1.8).
            self.congestion(now);
            self.cwr_pending = true;
        }
        if self.is_established() && now.saturating_duration_since(self.last_tx) >= KEEPALIVE {
            self.ack_now = true;
        }
    }

    fn fill(&mut self, now: Instant) {
        // Retransmits first, then new data while the windows allow.
        let resend: Vec<usize> = (0..self.in_flight.len()).filter(|&i| self.in_flight[i].resend).collect();
        for i in resend {
            let rto = self.rto();
            let f = &mut self.in_flight[i];
            f.resend = false;
            f.retransmits += 1;
            f.sent_at = now;
            f.deadline = f.deadline.max(now + rto);
            let (source, data) = (f.source, f.data.clone());
            self.transmit_source(source, &data);
        }
        // Congestion control limits packets not yet acknowledged; flow control (3.1.1.7) limits
        // the span from the oldest unacknowledged one, which the receiver must buffer.
        let mut outstanding = self.in_flight.iter().filter(|f| !f.acked).count();
        while outstanding < self.cwnd as usize
            && self.in_flight.len() < usize::from(self.peer_window)
            && let Some(data) = self.pending.pop_front()
        {
            outstanding += 1;
            let source = self.next_source;
            self.next_source = source.wrapping_add(1);
            self.transmit_source(source, &data);
            self.in_flight.push_back(InFlight {
                source,
                data,
                sent_at: now,
                deadline: now + self.rto(),
                retransmits: 0,
                acked: false,
                resend: false,
            });
        }
        if self.ack_now {
            self.push_ack();
        }
    }

    /// Queues an acknowledgement-only datagram.
    fn push_ack(&mut self) {
        if !self.is_established() {
            self.ack_now = true;
            return;
        }
        let mut flags = 0;
        if self.ack_delayed {
            // Not an RTT sample for the peer (3.1.6.3).
            flags |= wire::FLAG_ACKDELAYED;
        }
        if self.cn {
            flags |= wire::FLAG_CN;
        }
        let runs = self.ack_runs(MAX_ACK_RUNS);
        let d = wire::encode(&Outgoing {
            source_ack: self.source_ack(),
            receive_window: self.receive_window(),
            flags,
            ack_vector: &runs,
            ack_of_acks: None,
            source: None,
        });
        self.out.push_back(d);
        self.acked_now();
    }

    fn source_ack(&self) -> u32 {
        self.highest()
    }

    fn receive_window(&self) -> u16 {
        RECEIVE_WINDOW.saturating_sub(self.buffered.len() as u16).max(1)
    }

    fn acked_now(&mut self) {
        self.ack_now = false;
        self.ack_delayed = false;
        self.ack_deadline = None;
        self.unacked = 0;
    }

    fn transmit_source(&mut self, source: u32, data: &[u8]) {
        let coded = self.next_coded;
        self.next_coded = coded.wrapping_add(1);
        self.stats.sent += 1;
        let mut flags = 0;
        if self.cwr_pending {
            flags |= wire::FLAG_CWR;
            self.cwr_pending = false;
            self.cwr_seq = Some(source);
        }
        if self.cn {
            flags |= wire::FLAG_CN;
        }
        self.since_ack_of_acks += 1;
        let ack_of_acks = (self.since_ack_of_acks >= ACK_OF_ACKS_EVERY).then(|| {
            self.since_ack_of_acks = 0;
            // Everything up to the oldest unacknowledged packet is cumulatively acknowledged.
            self.in_flight.iter().find(|f| !f.acked).map_or(self.next_source, |f| f.source).wrapping_sub(1)
        });
        let runs = self.ack_runs(DATA_ACK_RUNS);
        let d = wire::encode(&Outgoing {
            source_ack: self.source_ack(),
            receive_window: self.receive_window(),
            flags,
            ack_vector: &runs,
            ack_of_acks,
            source: Some((coded, source, data)),
        });
        self.out.push_back(d);
        self.acked_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decides whether a datagram is lost: (towards the server?, index in that direction, bytes).
    type DropRule = Box<dyn FnMut(bool, usize, &[u8]) -> bool>;

    /// Two endpoints joined by a simulated network with a fixed one-way delay. `drop` decides,
    /// per datagram (by its index in send order, per direction), whether it is lost.
    struct Net {
        now: Instant,
        client: Conn,
        server: Option<Conn>,
        delay: Duration,
        /// (arrival, to_server, bytes)
        wire: Vec<(Instant, bool, Vec<u8>)>,
        sent: [usize; 2],
        drop: DropRule,
        server_isn: u32,
    }

    impl Net {
        fn new(client_isn: u32, server_isn: u32) -> Self {
            let now = Instant::now();
            Self {
                now,
                client: Conn::connect(now, client_isn),
                server: None,
                delay: Duration::from_millis(10),
                wire: Vec::new(),
                sent: [0, 0],
                drop: Box::new(|_, _, _| false),
                server_isn,
            }
        }

        fn flush(&mut self) {
            while let Some(d) = self.client.poll_transmit(self.now) {
                self.put(true, d);
            }
            if let Some(s) = self.server.as_mut() {
                let mut out = Vec::new();
                while let Some(d) = s.poll_transmit(self.now) {
                    out.push(d);
                }
                for d in out {
                    self.put(false, d);
                }
            }
        }

        fn put(&mut self, to_server: bool, d: Vec<u8>) {
            let i = &mut self.sent[usize::from(to_server)];
            let n = *i;
            *i += 1;
            if !(self.drop)(to_server, n, &d) {
                self.wire.push((self.now + self.delay, to_server, d));
            }
        }

        /// Advances to the next event (a delivery or a timer) and processes it.
        fn step(&mut self) -> bool {
            self.flush();
            let next_wire = self.wire.iter().map(|w| w.0).min();
            let timers = [self.client.poll_timeout(), self.server.as_ref().and_then(Conn::poll_timeout)];
            let Some(next) = next_wire.into_iter().chain(timers.into_iter().flatten()).min() else { return false };
            self.now = self.now.max(next);
            let now = self.now;
            let (due, rest): (Vec<_>, Vec<_>) = self.wire.drain(..).partition(|w| w.0 <= now);
            self.wire = rest;
            for (_, to_server, d) in due {
                if to_server {
                    match self.server.as_mut() {
                        Some(s) => s.handle_datagram(now, &d),
                        None => self.server = Conn::accept(now, &d, self.server_isn),
                    }
                } else {
                    self.client.handle_datagram(now, &d);
                }
            }
            true
        }

        fn run_until(&mut self, mut done: impl FnMut(&mut Self) -> bool, limit: Duration) {
            let end = self.now + limit;
            while !done(self) {
                assert!(
                    self.now < end,
                    "simulation did not finish in {limit:?}: client {}, server {}",
                    self.client.debug_state(),
                    self.server.as_ref().map_or_else(String::new, Conn::debug_state)
                );
                if !self.step() {
                    assert!(done(self), "no more events");
                    return;
                }
            }
        }

        fn server(&mut self) -> &mut Conn {
            self.server.as_mut().unwrap()
        }
    }

    fn chunks(n: usize, size: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| (0..size).map(|j| (i * 31 + j) as u8).collect()).collect()
    }

    /// Sends `data` from one side and checks it all arrives, in order, on the other.
    fn transfer(net: &mut Net, data: &[Vec<u8>], from_client: bool, limit: Duration) {
        for d in data {
            if from_client { net.client.send(d.clone()) } else { net.server().send(d.clone()) }
        }
        let mut got = Vec::new();
        net.run_until(
            |n| {
                let rx = if from_client { n.server() } else { &mut n.client };
                while let Some(d) = rx.recv() {
                    got.push(d);
                }
                got.len() >= data.len()
            },
            limit,
        );
        assert_eq!(got, data);
        // Everything ends up acknowledged.
        net.run_until(|n| if from_client { n.client.queued() == 0 } else { n.server().queued() == 0 }, limit);
    }

    fn established(net: &mut Net) {
        net.run_until(
            |n| n.client.is_established() && n.server.as_ref().is_some_and(Conn::is_established),
            Duration::from_secs(5),
        );
    }

    #[test]
    fn handshake_negotiates_version_2_and_mtu() {
        let mut net = Net::new(100, 9000);
        let syn = net.client.poll_transmit(net.now).unwrap();
        assert_eq!(syn.len(), 1232, "SYN is padded to the MTU");
        let d = wire::decode(&syn).unwrap();
        assert_eq!(d.syn.unwrap().version, Some(wire::VERSION_2));
        net.put(true, syn);
        established(&mut net);
        assert_eq!(net.client.version(), wire::VERSION_2);
        assert_eq!(net.server().version(), wire::VERSION_2);
        assert_eq!(net.client.max_payload(), 1232 - wire::data_headers_len(DATA_ACK_RUNS, true));
    }

    #[test]
    fn transfers_both_ways_without_loss() {
        let mut net = Net::new(1, 2);
        established(&mut net);
        transfer(&mut net, &chunks(300, 1000), true, Duration::from_secs(10));
        transfer(&mut net, &chunks(500, 1100), false, Duration::from_secs(10));
        assert!(net.client.rtt().is_some_and(|r| r >= Duration::from_millis(20)));
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut net = Net::new(u32::MAX - 5, u32::MAX - 50);
        established(&mut net);
        transfer(&mut net, &chunks(200, 64), true, Duration::from_secs(10));
        transfer(&mut net, &chunks(200, 64), false, Duration::from_secs(10));
    }

    #[test]
    fn recovers_from_typical_loss_quickly() {
        let mut net = Net::new(77, 1_000_000);
        established(&mut net);
        // About 5 % loss each way after the handshake (Wi-Fi on a bad day).
        net.drop = Box::new(|to_server, i, _| if to_server { i > 2 && i % 23 == 0 } else { i > 2 && i % 19 == 0 });
        let start = net.now;
        transfer(&mut net, &chunks(2000, 900), false, Duration::from_secs(60));
        let took = net.now - start;
        transfer(&mut net, &chunks(300, 900), true, Duration::from_secs(60));
        assert!(net.server().stats().timeout_retransmits <= 5, "{:?}", net.server().stats());
        // 1.8 MB at 20 ms RTT and 5 % loss: NewReno manages about 250 packets a second.
        assert!(took < Duration::from_secs(12), "took {took:?}: {}", net.server().debug_state());
    }

    #[test]
    fn survives_heavy_loss() {
        let mut net = Net::new(77, 1_000_000);
        established(&mut net);
        // Every 7th server and every 5th client datagram lost, including retransmits.
        net.drop = Box::new(|to_server, i, _| if to_server { i > 2 && i % 5 == 0 } else { i > 2 && i % 7 == 0 });
        transfer(&mut net, &chunks(1000, 900), false, Duration::from_secs(300));
        transfer(&mut net, &chunks(200, 900), true, Duration::from_secs(300));
        assert!(net.client.is_established() && net.server().is_established());
    }

    #[test]
    fn loss_triggers_cn_then_cwr() {
        let mut net = Net::new(5, 500);
        established(&mut net);
        let mut saw_cn = false;
        let mut saw_cwr_after_cn = false;
        let flags = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let f = flags.clone();
        net.drop = Box::new(move |to_server, i, d| {
            let fl = wire::decode(d).map(|d| d.flags).unwrap_or(0);
            f.borrow_mut().push((to_server, fl));
            // Lose one data datagram from the server early on.
            !to_server && i == 4
        });
        transfer(&mut net, &chunks(100, 500), false, Duration::from_secs(10));
        for (to_server, fl) in flags.borrow().iter() {
            if *to_server && fl & wire::FLAG_CN != 0 {
                saw_cn = true;
            }
            if !*to_server && saw_cn && fl & wire::FLAG_CWR != 0 {
                saw_cwr_after_cn = true;
            }
        }
        assert!(saw_cn, "the client reports the gap with CN");
        assert!(saw_cwr_after_cn, "the server answers with CWR");
    }

    #[test]
    fn handles_reordering_and_duplicates() {
        let mut net = Net::new(10, 20);
        established(&mut net);
        // Duplicate every server datagram and deliver alternate ones late.
        let mut late = Vec::new();
        for (i, d) in chunks(200, 300).into_iter().enumerate() {
            net.server().send(d);
            if i % 50 == 49 {
                net.flush();
                for (_, to_server, d) in net.wire.drain(..) {
                    late.push((to_server, d));
                }
            }
        }
        net.flush();
        let mut extra: Vec<_> = net.wire.drain(..).map(|(_, t, d)| (t, d)).collect();
        extra.extend(late);
        extra.reverse();
        let now = net.now;
        for (i, (to_server, d)) in extra.into_iter().enumerate() {
            let at = now + Duration::from_millis(5 + (i % 3) as u64);
            net.wire.push((at, to_server, d.clone()));
            net.wire.push((at + Duration::from_millis(1), to_server, d));
        }
        let mut got = Vec::new();
        net.run_until(
            |n| {
                while let Some(d) = n.client.recv() {
                    got.push(d);
                }
                got.len() >= 200
            },
            Duration::from_secs(10),
        );
        assert_eq!(got, chunks(200, 300));
        net.run_until(|n| n.server().queued() == 0, Duration::from_secs(10));
    }

    #[test]
    fn accepts_a_first_packet_numbered_isn() {
        // MS-RDPEUDP 3.1.1 says the first Source Packet carries the ISN itself; 3.1.5.1.4 says
        // ISN + 1. Bastion sends ISN + 1 but must accept both.
        let mut net = Net::new(1, 1000);
        established(&mut net);
        let d = wire::encode(&Outgoing {
            source_ack: 1,
            receive_window: 64,
            ack_vector: &[],
            source: Some((1000, 1000, b"first")),
            ..Default::default()
        });
        net.client.handle_datagram(net.now, &d);
        assert_eq!(net.client.recv().as_deref(), Some(&b"first"[..]));
        // A lone in-order packet is acknowledged by the delayed-ACK timer.
        let later = net.now + Duration::from_millis(250);
        let ack = net.client.poll_transmit(later).unwrap();
        assert_ne!(wire::decode(&ack).unwrap().flags & wire::FLAG_ACKDELAYED, 0);
        let a = wire::decode(&ack).unwrap();
        assert_eq!(a.source_ack, 1000);
        assert_eq!(a.ack_vector.unwrap(), vec![Run { state: STATE_RECEIVED, len: 1 }]);
    }

    #[test]
    fn ack_vector_reports_gaps_and_respects_ack_of_acks() {
        let now = Instant::now();
        let mut c = Conn::connect(now, 1);
        let syn = c.poll_transmit(now).unwrap();
        let mut s = Conn::accept(now, &syn, 100).unwrap();
        c.handle_datagram(now, &s.poll_transmit(now).unwrap());
        let src = |seq: u32, aoa: Option<u32>| {
            wire::encode(&Outgoing {
                source_ack: 1,
                receive_window: 64,
                ack_vector: &[],
                ack_of_acks: aoa,
                source: Some((seq, seq, b"x")),
                ..Default::default()
            })
        };
        // 101, 102 received; 103, 104 lost; 105 received.
        for seq in [101, 102, 105] {
            c.handle_datagram(now, &src(seq, None));
        }
        let mut last = None;
        while let Some(d) = c.poll_transmit(now) {
            last = Some(d);
        }
        let a = wire::decode(last.as_ref().unwrap()).unwrap();
        assert_eq!(a.source_ack, 105);
        assert_eq!(
            a.ack_vector.unwrap(),
            vec![
                Run { state: STATE_RECEIVED, len: 2 },
                Run { state: STATE_NOT_RECEIVED, len: 2 },
                Run { state: STATE_RECEIVED, len: 1 }
            ]
        );
        // The peer says it processed acknowledgements up to 102: the vector starts at 103.
        c.handle_datagram(now, &src(106, Some(102)));
        let mut last = None;
        while let Some(d) = c.poll_transmit(now) {
            last = Some(d);
        }
        let a = wire::decode(last.as_ref().unwrap()).unwrap();
        assert_eq!(a.source_ack, 106);
        assert_eq!(
            a.ack_vector.unwrap(),
            vec![Run { state: STATE_NOT_RECEIVED, len: 2 }, Run { state: STATE_RECEIVED, len: 2 }]
        );
        // A reset point beyond the gap is ignored past what was delivered.
        c.handle_datagram(now, &src(107, Some(106)));
        let mut last = None;
        while let Some(d) = c.poll_transmit(now) {
            last = Some(d);
        }
        let runs = wire::decode(last.as_ref().unwrap()).unwrap().ack_vector.unwrap();
        assert_eq!(runs.first(), Some(&Run { state: STATE_NOT_RECEIVED, len: 2 }));
        let _ = &mut s;
    }

    #[test]
    fn long_runs_are_split_at_63() {
        let mut net = Net::new(1, 2);
        established(&mut net);
        transfer(&mut net, &chunks(130, 10), false, Duration::from_secs(10));
        // Runs never exceed 63 and together cover exactly the tracked range.
        let runs = net.client.ack_runs(MAX_ACK_RUNS);
        assert!(runs.iter().all(|r| r.len <= 63));
        assert_eq!(runs.iter().map(|r| u32::from(r.len)).sum::<u32>(), net.client.got.len() as u32);
    }

    #[test]
    fn a_twice_lost_packet_on_a_fast_link_is_recovered_not_fatal() {
        // A 2 ms round trip (a home LAN). Packet 4 from the client is lost twice: the original
        // and its fast retransmit. Re-sending it on every later acknowledgement would use up the
        // retransmit limit within milliseconds; the time-out must recover it instead.
        let mut net = Net::new(1000, 2);
        net.delay = Duration::from_millis(1);
        established(&mut net);
        let mut lost = 0;
        net.drop = Box::new(move |to_server, _, d| {
            let hit = to_server
                && matches!(wire::decode(d).map(|d| d.payload), Ok(Some(Payload::Source { source: 1004, .. })));
            if hit && lost < 2 {
                lost += 1;
                return true;
            }
            false
        });
        transfer(&mut net, &chunks(400, 500), true, Duration::from_secs(10));
        assert!(net.client.is_established());
        let s = net.client.stats();
        assert_eq!(s.fast_retransmits, 1, "{s:?}");
        assert_eq!(s.timeout_retransmits, 1, "{s:?}");
    }

    #[test]
    fn diagnostics_list_the_peers_recent_acknowledgements() {
        let mut net = Net::new(1, 2);
        established(&mut net);
        transfer(&mut net, &chunks(30, 100), true, Duration::from_secs(5));
        let d = net.client.diagnostics();
        assert!(d.contains("recent acks") && d.contains("0x0004 [0:"), "{d}");
    }

    #[test]
    fn handshake_retries_then_gives_up() {
        let mut net = Net::new(1, 2);
        net.drop = Box::new(|to_server, _, _| to_server);
        net.run_until(|n| n.client.closed().is_some(), Duration::from_secs(10));
        assert_eq!(net.client.closed(), Some(Closed::HandshakeTimeout));
        assert_eq!(net.sent[1], SYN_ATTEMPTS as usize);
    }

    #[test]
    fn lost_syn_ack_is_resent() {
        let mut net = Net::new(1, 2);
        net.drop = Box::new(|to_server, i, _| !to_server && i == 0);
        established(&mut net);
        transfer(&mut net, &chunks(10, 100), true, Duration::from_secs(10));
    }

    #[test]
    fn closes_when_data_is_never_acknowledged() {
        let mut net = Net::new(1, 2);
        established(&mut net);
        net.drop = Box::new(|to_server, _, _| to_server);
        net.client.send(vec![1; 10]);
        net.run_until(|n| n.client.closed().is_some(), Duration::from_secs(60));
        assert_eq!(net.client.closed(), Some(Closed::RetransmitLimit));
    }

    #[test]
    fn idle_peer_times_out_and_keepalives_keep_a_quiet_link_open() {
        let mut net = Net::new(1, 2);
        established(&mut net);
        // Quiet but both alive: keepalives flow and nobody closes.
        let start = net.now;
        net.run_until(|n| n.now >= start + Duration::from_secs(200), Duration::from_secs(300));
        assert!(net.client.is_established() && net.server().is_established());
        // Peer gone.
        net.drop = Box::new(|to_server, _, _| !to_server);
        net.run_until(|n| n.client.closed().is_some(), Duration::from_secs(100));
        assert_eq!(net.client.closed(), Some(Closed::IdleTimeout));
    }

    #[test]
    fn respects_the_peer_receive_window() {
        let now = Instant::now();
        let mut c = Conn::connect(now, 1);
        let syn = c.poll_transmit(now).unwrap();
        let mut s = Conn::accept(now, &syn, 100).unwrap();
        c.handle_datagram(now, &s.poll_transmit(now).unwrap());
        // The server advertises room for 3 datagrams.
        c.handle_datagram(now, &wire::encode(&Outgoing { source_ack: 100, receive_window: 3, ..Default::default() }));
        for d in chunks(10, 10) {
            c.send(d);
        }
        let mut data = 0;
        while let Some(d) = c.poll_transmit(now) {
            if wire::decode(&d).unwrap().payload.is_some() {
                data += 1;
            }
        }
        assert_eq!(data, 3);
    }
}
