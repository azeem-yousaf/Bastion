//! MS-RDPEMT tunnel PDUs, carried inside the TLS stream of the UDP transport. Little-endian.
//!
//! `RDP_TUNNEL_HEADER`: Action (low 4 bits) and Flags (high 4 bits, zero) in one byte,
//! PayloadLength (u16, excluding the header), HeaderLength (u8, 4 + subheaders), then
//! subheaders — each starting with its own length and type byte (auto-detect requests and
//! responses, which are the MS-RDPBCGR auto-detect structures themselves).

pub const ACTION_CREATE_REQUEST: u8 = 0x0;
pub const ACTION_CREATE_RESPONSE: u8 = 0x1;
pub const ACTION_DATA: u8 = 0x2;

pub const SUBHEADER_AUTODETECT_REQUEST: u8 = 0x00;
pub const SUBHEADER_AUTODETECT_RESPONSE: u8 = 0x01;

const HEADER_LEN: usize = 4;
/// Largest payload one tunnel PDU can carry.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub action: u8,
    /// Raw subheaders, each including its length and type bytes.
    pub subheaders: Vec<Vec<u8>>,
    pub payload: Vec<u8>,
}

impl Pdu {
    /// `HrResponse` of a Tunnel Create Response.
    pub fn create_response(&self) -> Option<u32> {
        (self.action == ACTION_CREATE_RESPONSE && self.payload.len() >= 4)
            .then(|| u32::from_le_bytes([self.payload[0], self.payload[1], self.payload[2], self.payload[3]]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid tunnel header length {0}")]
    HeaderLength(u8),
    #[error("invalid tunnel subheader")]
    Subheader,
    #[error("tunnel payload of {0} bytes is too large")]
    TooLarge(usize),
}

fn encode(action: u8, subheaders: &[&[u8]], payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::TooLarge(payload.len()));
    }
    let header_len = HEADER_LEN + subheaders.iter().map(|s| s.len()).sum::<usize>();
    let header_len = u8::try_from(header_len).map_err(|_| Error::Subheader)?;
    let mut out = Vec::with_capacity(usize::from(header_len) + payload.len());
    out.push(action & 0x0f);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.push(header_len);
    for s in subheaders {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(payload);
    Ok(out)
}

/// `RDP_TUNNEL_CREATEREQUEST` with the request ID and cookie from the Initiate Multitransport
/// Request received over TCP.
pub fn create_request(request_id: u32, cookie: &[u8; 16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(24);
    payload.extend_from_slice(&request_id.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(cookie);
    encode(ACTION_CREATE_REQUEST, &[], &payload).expect("fixed-size PDU")
}

/// `RDP_TUNNEL_DATA` carrying one dynamic-channel PDU and optional subheaders.
pub fn data(payload: &[u8], subheaders: &[&[u8]]) -> Result<Vec<u8>, Error> {
    encode(ACTION_DATA, subheaders, payload)
}

/// Splits the decrypted byte stream back into tunnel PDUs.
#[derive(Debug, Default)]
pub struct Reassembler {
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_pdu(&mut self) -> Result<Option<Pdu>, Error> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let action = self.buf[0] & 0x0f;
        let payload_len = usize::from(u16::from_le_bytes([self.buf[1], self.buf[2]]));
        let header_len = self.buf[3];
        if usize::from(header_len) < HEADER_LEN {
            return Err(Error::HeaderLength(header_len));
        }
        let total = usize::from(header_len) + payload_len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let mut subheaders = Vec::new();
        let mut rest = &self.buf[HEADER_LEN..usize::from(header_len)];
        while !rest.is_empty() {
            let len = usize::from(rest[0]);
            if len < 2 || len > rest.len() {
                return Err(Error::Subheader);
            }
            subheaders.push(rest[..len].to_vec());
            rest = &rest[len..];
        }
        let payload = self.buf[usize::from(header_len)..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(Pdu { action, subheaders, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn create_request_matches_the_spec_example() {
        // MS-RDPEMT 4.1.
        let cookie: [u8; 16] = hex("e2 f0 d1 08 56 7f b4 3a dc f4 b3 dc 16 92 1e 3a").try_into().unwrap();
        assert_eq!(
            create_request(7, &cookie),
            hex("00 18 00 04 07 00 00 00 00 00 00 00 e2 f0 d1 08 56 7f b4 3a dc f4 b3 dc 16 92 1e 3a")
        );
    }

    #[test]
    fn decodes_the_spec_create_response() {
        // MS-RDPEMT 4.2, delivered one byte at a time.
        let mut r = Reassembler::default();
        let bytes = hex("01 04 00 04 00 00 00 00");
        for (i, b) in bytes.iter().enumerate() {
            r.push(&[*b]);
            let p = r.next_pdu().unwrap();
            if i + 1 < bytes.len() {
                assert!(p.is_none());
            } else {
                assert_eq!(p.unwrap().create_response(), Some(0));
            }
        }
    }

    #[test]
    fn data_pdus_round_trip_with_subheaders() {
        let sub = hex("06 00 01 00 14 00"); // a Bandwidth Measure Start (reliable UDP)
        let a = data(b"hello", &[&sub]).unwrap();
        assert_eq!(&a[..4], &[0x02, 5, 0, 10]);
        let b = data(b"", &[]).unwrap();
        let mut r = Reassembler::default();
        r.push(&a);
        r.push(&b);
        r.push(&a[..3]);
        assert_eq!(
            r.next_pdu().unwrap(),
            Some(Pdu { action: ACTION_DATA, subheaders: vec![sub], payload: b"hello".to_vec() })
        );
        assert_eq!(r.next_pdu().unwrap(), Some(Pdu { action: ACTION_DATA, subheaders: vec![], payload: vec![] }));
        assert_eq!(r.next_pdu().unwrap(), None);
    }

    #[test]
    fn rejects_bad_headers_and_oversized_payloads() {
        let mut r = Reassembler::default();
        r.push(&[0x02, 0, 0, 3]);
        assert_eq!(r.next_pdu(), Err(Error::HeaderLength(3)));
        let mut r = Reassembler::default();
        r.push(&[0x02, 0, 0, 6, 9, 0]);
        assert_eq!(r.next_pdu(), Err(Error::Subheader));
        assert_eq!(data(&vec![0; MAX_PAYLOAD + 1], &[]), Err(Error::TooLarge(MAX_PAYLOAD + 1)));
    }
}
