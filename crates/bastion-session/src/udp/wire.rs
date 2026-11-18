//! MS-RDPEUDP (versions 1 and 2) datagram layout. Every field is in network byte order.
//!
//! A datagram is an `RDPUDP_FEC_HEADER`, then — depending on its flags — the SYN payloads, an
//! ACK vector (padded to a 4-byte boundary), an ACK-of-ACKs reset point, and a Source or FEC
//! payload header followed by the data. The order follows the byte-level examples in
//! MS-RDPEUDP section 4.

pub const FLAG_SYN: u16 = 0x0001;
pub const FLAG_ACK: u16 = 0x0004;
pub const FLAG_DATA: u16 = 0x0008;
pub const FLAG_FEC: u16 = 0x0010;
pub const FLAG_CN: u16 = 0x0020;
pub const FLAG_CWR: u16 = 0x0040;
pub const FLAG_ACK_OF_ACKS: u16 = 0x0100;
pub const FLAG_SYNLOSSY: u16 = 0x0200;
pub const FLAG_ACKDELAYED: u16 = 0x0400;
pub const FLAG_CORRELATION_ID: u16 = 0x0800;
pub const FLAG_SYNEX: u16 = 0x1000;

pub const SYNEX_VERSION_INFO_VALID: u16 = 0x0001;
pub const VERSION_1: u16 = 0x0001;
pub const VERSION_2: u16 = 0x0002;
/// MS-RDPEUDP2: a different data-transfer protocol, which we never offer.
pub const VERSION_3: u16 = 0x0101;

/// Allowed MTU range (MS-RDPEUDP 2.2.2.5).
pub const MTU_MIN: u16 = 1132;
pub const MTU_MAX: u16 = 1232;

/// ACK vector element states (2.2.1.1).
pub const STATE_RECEIVED: u8 = 0;
pub const STATE_NOT_RECEIVED: u8 = 3;
/// Longest run one ACK vector element can describe (six bits).
pub const MAX_RUN: u8 = 63;

const FEC_HEADER_LEN: usize = 8;
const SOURCE_HEADER_LEN: usize = 8;

/// Fixed size of a datagram's headers when it carries data: FEC header, empty ACK vector, Source
/// header. The ACK vector's elements and padding come on top.
pub const DATA_OVERHEAD: usize = FEC_HEADER_LEN + 2 + SOURCE_HEADER_LEN;

/// `true` when `a` comes before `b` in the wrapping 32-bit sequence space (RFC 793 3.3).
pub fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// One run in an ACK vector: `len` consecutive Source Packets in `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub state: u8,
    pub len: u8,
}

impl Run {
    pub fn encode(self) -> u8 {
        (self.state << 6) | (self.len & 0x3f)
    }

    pub fn decode(b: u8) -> Self {
        Self { state: b >> 6, len: b & 0x3f }
    }
}

/// `RDPUDP_SYNDATA_PAYLOAD` plus the optional SYNEX version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syn {
    pub initial_seq: u32,
    pub up_mtu: u16,
    pub down_mtu: u16,
    /// `Some` when an `RDPUDP_SYNDATAEX_PAYLOAD` with a valid version is present.
    pub version: Option<u16>,
}

/// Payload header of a data datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    /// `RDPUDP_SOURCE_PAYLOAD_HEADER`: data the receiver must deliver.
    Source { coded: u32, source: u32 },
    /// `RDPUDP_FEC_PAYLOAD_HEADER`: redundancy for recovering lost Source Packets. Optional to use.
    Fec { coded: u32, source_start: u32, range: u8, fec_index: u8 },
}

/// A decoded datagram. `data` borrows from the received buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub source_ack: u32,
    pub receive_window: u16,
    pub flags: u16,
    pub syn: Option<Syn>,
    pub ack_vector: Option<Vec<Run>>,
    pub ack_of_acks: Option<u32>,
    pub payload: Option<Payload>,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("datagram truncated")]
    Truncated,
    #[error("invalid MTU {0}")]
    BadMtu(u16),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or(DecodeError::Truncated)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

pub fn decode(buf: &[u8]) -> Result<Datagram<'_>, DecodeError> {
    let mut r = Reader { buf, pos: 0 };
    let source_ack = r.u32()?;
    let receive_window = r.u16()?;
    let flags = r.u16()?;
    let mut d = Datagram {
        source_ack,
        receive_window,
        flags,
        syn: None,
        ack_vector: None,
        ack_of_acks: None,
        payload: None,
        data: &[],
    };
    if flags & FLAG_SYN != 0 {
        let initial_seq = r.u32()?;
        let up_mtu = r.u16()?;
        let down_mtu = r.u16()?;
        for m in [up_mtu, down_mtu] {
            if !(MTU_MIN..=MTU_MAX).contains(&m) {
                return Err(DecodeError::BadMtu(m));
            }
        }
        if flags & FLAG_CORRELATION_ID != 0 {
            r.take(32)?; // uCorrelationId + uReserved
        }
        let mut version = None;
        if flags & FLAG_SYNEX != 0 {
            let synex_flags = r.u16()?;
            if synex_flags & SYNEX_VERSION_INFO_VALID != 0 {
                let v = r.u16()?;
                version = Some(v);
                if v == VERSION_3 {
                    r.take(32)?; // cookieHash
                }
            }
        }
        d.syn = Some(Syn { initial_seq, up_mtu, down_mtu, version });
        // SYN datagrams are zero-padded to the MTU; nothing else follows.
        return Ok(d);
    }
    if flags & FLAG_ACK != 0 {
        let n = usize::from(r.u16()?);
        let runs = r.take(n)?.iter().map(|&b| Run::decode(b)).collect();
        r.take(pad4(2 + n))?;
        d.ack_vector = Some(runs);
    }
    if flags & FLAG_ACK_OF_ACKS != 0 {
        d.ack_of_acks = Some(r.u32()?);
    }
    if flags & FLAG_DATA != 0 {
        d.payload = Some(if flags & FLAG_FEC != 0 {
            let coded = r.u32()?;
            let source_start = r.u32()?;
            let range = r.u8()?;
            let fec_index = r.u8()?;
            r.take(2)?;
            Payload::Fec { coded, source_start, range, fec_index }
        } else {
            Payload::Source { coded: r.u32()?, source: r.u32()? }
        });
        d.data = &buf[r.pos..];
    }
    Ok(d)
}

/// Bytes of zero padding that make a structure of `len` bytes end on a 4-byte boundary.
fn pad4(len: usize) -> usize {
    (4 - len % 4) % 4
}

fn header(out: &mut Vec<u8>, source_ack: u32, receive_window: u16, flags: u16) {
    out.extend_from_slice(&source_ack.to_be_bytes());
    out.extend_from_slice(&receive_window.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
}

/// A SYN (client) or SYN+ACK (server, `ack_of` = the client's initial sequence number),
/// zero-padded to `pad_to` bytes as MS-RDPEUDP 3.1.5.1.1 requires.
pub fn encode_syn(syn: Syn, receive_window: u16, ack_of: Option<u32>, pad_to: usize) -> Vec<u8> {
    let mut flags = FLAG_SYN;
    if ack_of.is_some() {
        flags |= FLAG_ACK;
    }
    if syn.version.is_some() {
        flags |= FLAG_SYNEX;
    }
    let mut out = Vec::with_capacity(pad_to);
    header(&mut out, ack_of.unwrap_or(u32::MAX), receive_window, flags);
    out.extend_from_slice(&syn.initial_seq.to_be_bytes());
    out.extend_from_slice(&syn.up_mtu.to_be_bytes());
    out.extend_from_slice(&syn.down_mtu.to_be_bytes());
    if let Some(v) = syn.version {
        out.extend_from_slice(&SYNEX_VERSION_INFO_VALID.to_be_bytes());
        out.extend_from_slice(&v.to_be_bytes());
    }
    if out.len() < pad_to {
        out.resize(pad_to, 0);
    }
    out
}

/// What goes into a non-SYN datagram.
#[derive(Debug, Clone, Default)]
pub struct Outgoing<'a> {
    pub source_ack: u32,
    pub receive_window: u16,
    /// Extra flags (CN, CWR, ACKDELAYED). ACK, DATA and ACK_OF_ACKS follow from the fields.
    pub flags: u16,
    pub ack_vector: &'a [Run],
    pub ack_of_acks: Option<u32>,
    /// `(snCoded, snSourceStart, data)` for a Source Packet.
    pub source: Option<(u32, u32, &'a [u8])>,
}

pub fn encode(o: &Outgoing<'_>) -> Vec<u8> {
    let mut flags = o.flags | FLAG_ACK;
    if o.ack_of_acks.is_some() {
        flags |= FLAG_ACK_OF_ACKS;
    }
    if o.source.is_some() {
        flags |= FLAG_DATA;
    }
    let data_len = o.source.map_or(0, |(_, _, d)| d.len());
    let mut out = Vec::with_capacity(DATA_OVERHEAD + o.ack_vector.len() + 8 + data_len);
    header(&mut out, o.source_ack, o.receive_window, flags);
    let n = o.ack_vector.len();
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend(o.ack_vector.iter().map(|r| r.encode()));
    out.resize(out.len() + pad4(2 + n), 0);
    if let Some(reset) = o.ack_of_acks {
        out.extend_from_slice(&reset.to_be_bytes());
    }
    if let Some((coded, source, data)) = o.source {
        out.extend_from_slice(&coded.to_be_bytes());
        out.extend_from_slice(&source.to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// Bytes an ACK vector of `runs` elements adds to a datagram (size field and padding included).
pub fn ack_vector_len(runs: usize) -> usize {
    2 + runs + pad4(2 + runs)
}

/// Size of the fixed headers in front of the data, for a given ACK vector length.
pub fn data_headers_len(runs: usize, ack_of_acks: bool) -> usize {
    FEC_HEADER_LEN + ack_vector_len(runs) + if ack_of_acks { 4 } else { 0 } + SOURCE_HEADER_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn decodes_the_spec_syn_example() {
        // MS-RDPEUDP 4.1.1 (CORRELATION_ID | SYNLOSSY | SYN), zero-padded to 1232 bytes.
        let mut b = hex("ff ff ff ff 04 00 0A 01 00 00 00 42 04 D0 04 D0 \
             D2 35 AC 43 89 41 42 DA B1 0E DD 68 87 F7 F9 FB 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        b.resize(1232, 0);
        let d = decode(&b).unwrap();
        assert_eq!(d.source_ack, u32::MAX);
        assert_eq!(d.receive_window, 1024);
        assert_eq!(d.flags, FLAG_SYN | FLAG_SYNLOSSY | FLAG_CORRELATION_ID);
        assert_eq!(d.syn, Some(Syn { initial_seq: 0x42, up_mtu: 1232, down_mtu: 1232, version: None }));
    }

    #[test]
    fn encodes_a_syn_ack_like_the_spec_example() {
        // MS-RDPEUDP 4.1.2: SYN+ACK acknowledging initial sequence number 0x42.
        let syn = Syn { initial_seq: 0x42, up_mtu: 1232, down_mtu: 1232, version: None };
        let b = encode_syn(syn, 1024, Some(0x42), 1232);
        assert_eq!(b.len(), 1232);
        assert_eq!(&b[..16], &hex("00 00 00 42 04 00 00 05 00 00 00 42 04 D0 04 D0")[..]);
        assert!(b[16..].iter().all(|&x| x == 0));
    }

    #[test]
    fn syn_with_version_carries_synex() {
        let syn = Syn { initial_seq: 7, up_mtu: 1232, down_mtu: 1200, version: Some(VERSION_2) };
        let b = encode_syn(syn, 64, None, 1200);
        assert_eq!(b.len(), 1200);
        let d = decode(&b).unwrap();
        assert_eq!(d.flags, FLAG_SYN | FLAG_SYNEX);
        assert_eq!(d.source_ack, u32::MAX);
        assert_eq!(d.syn, Some(syn));
    }

    #[test]
    fn decodes_the_spec_source_packet_example() {
        // MS-RDPEUDP 4.2.1: ACK vector of one element (4 received) padded to 4 bytes, then the
        // Source header and a TLS record.
        let b = hex("d6 cf 0a b8 04 00 00 0c 00 01 04 00 ec 47 1a e4 ec 47 1a e4 17 03 03 00 40 bb");
        let d = decode(&b).unwrap();
        assert_eq!(d.source_ack, 0xd6cf_0ab8);
        assert_eq!(d.ack_vector, Some(vec![Run { state: STATE_RECEIVED, len: 4 }]));
        assert_eq!(d.payload, Some(Payload::Source { coded: 0xec47_1ae4, source: 0xec47_1ae4 }));
        assert_eq!(d.data, &hex("17 03 03 00 40 bb")[..]);
    }

    #[test]
    fn decodes_the_spec_ack_of_acks_example() {
        // MS-RDPEUDP 4.2.3: the reset point sits between the ACK vector and the Source header.
        let b = hex("d6 cf 0a b8 04 00 01 0c 00 01 04 00 d6 cf 0a b8 ec 47 1a e4 ec 47 1a e4 17 03 03 00");
        let d = decode(&b).unwrap();
        assert_eq!(d.ack_of_acks, Some(0xd6cf_0ab8));
        assert_eq!(d.payload, Some(Payload::Source { coded: 0xec47_1ae4, source: 0xec47_1ae4 }));
        assert_eq!(d.data, &hex("17 03 03 00")[..]);
    }

    #[test]
    fn decodes_fec_packets() {
        let b = hex("d6 cf 0a cb 04 00 00 1c 00 01 04 00 ec 47 1a fd ec 47 1a fd 10 01 00 00 40 25 04 f1");
        let d = decode(&b).unwrap();
        assert_eq!(
            d.payload,
            Some(Payload::Fec { coded: 0xec47_1afd, source_start: 0xec47_1afd, range: 16, fec_index: 1 })
        );
        assert_eq!(d.data, &hex("40 25 04 f1")[..]);
    }

    #[test]
    fn encode_reproduces_the_spec_examples() {
        let runs = [Run { state: STATE_RECEIVED, len: 4 }];
        let data = hex("17 03 03 00 40 bb");
        let src = encode(&Outgoing {
            source_ack: 0xd6cf_0ab8,
            receive_window: 1024,
            ack_vector: &runs,
            source: Some((0xec47_1ae4, 0xec47_1ae4, &data)),
            ..Default::default()
        });
        assert_eq!(src, hex("d6 cf 0a b8 04 00 00 0c 00 01 04 00 ec 47 1a e4 ec 47 1a e4 17 03 03 00 40 bb"));
        let tail = hex("17 03 03 00");
        let aoa = encode(&Outgoing {
            source_ack: 0xd6cf_0ab8,
            receive_window: 1024,
            ack_vector: &runs,
            ack_of_acks: Some(0xd6cf_0ab8),
            source: Some((0xec47_1ae4, 0xec47_1ae4, &tail)),
            ..Default::default()
        });
        assert_eq!(aoa, hex("d6 cf 0a b8 04 00 01 0c 00 01 04 00 d6 cf 0a b8 ec 47 1a e4 ec 47 1a e4 17 03 03 00"));
        assert_eq!(data_headers_len(1, true), aoa.len() - tail.len());
    }

    #[test]
    fn ack_vector_padding_for_every_length() {
        for n in 0..9usize {
            let runs = vec![Run { state: STATE_NOT_RECEIVED, len: 1 }; n];
            let b = encode(&Outgoing { ack_vector: &runs, ..Default::default() });
            assert_eq!((b.len() - 8) % 4, 0, "{n} elements");
            assert_eq!(b.len() - 8, ack_vector_len(n));
            assert_eq!(decode(&b).unwrap().ack_vector.unwrap(), runs);
        }
    }

    #[test]
    fn truncated_and_invalid_datagrams_are_rejected() {
        let b = hex("d6 cf 0a b8 04 00 00 0c 00 05 04");
        assert_eq!(decode(&b), Err(DecodeError::Truncated));
        assert_eq!(decode(&b[..5]), Err(DecodeError::Truncated));
        let mut syn = encode_syn(Syn { initial_seq: 1, up_mtu: 1232, down_mtu: 1232, version: None }, 8, None, 64);
        syn[12] = 0xff; // uUpStreamMtu = 0xffd0
        assert!(matches!(decode(&syn), Err(DecodeError::BadMtu(_))));
    }

    #[test]
    fn sequence_comparison_wraps() {
        assert!(seq_before(1, 2));
        assert!(!seq_before(2, 1));
        assert!(!seq_before(5, 5));
        assert!(seq_before(u32::MAX, 0));
        assert!(seq_before(u32::MAX - 10, 3));
        assert!(!seq_before(3, u32::MAX - 10));
    }

    #[test]
    fn run_encoding() {
        assert_eq!(Run { state: STATE_NOT_RECEIVED, len: 63 }.encode(), 0xff);
        assert_eq!(Run::decode(0x04), Run { state: STATE_RECEIVED, len: 4 });
        assert_eq!(Run::decode(0xc2), Run { state: STATE_NOT_RECEIVED, len: 2 });
    }
}
