//! Runs a static-channel processor on a dynamic channel of the same name.
//!
//! With a UDP tunnel up, Windows opens some static channels again as dynamic channels so their
//! traffic can use the tunnel: `rdpdr` (device redirection), `cliprdr`, ... It never opens audio
//! output until the dynamic `rdpdr` is accepted (live sessions: declining it left the session
//! silent, while over TCP the static `rdpdr` suffices). The PDUs are the same; only the framing
//! differs, and DRDYNVC handles that, so the static processor is reused as is.

use ironrdp_core::{Encode, EncodeResult, WriteCursor};
use ironrdp_dvc::{DvcClientProcessor, DvcEncode, DvcMessage, DvcProcessor};
use ironrdp_pdu::PduResult;
use ironrdp_svc::{SvcMessage, SvcProcessor};

/// A static-channel processor answering on the dynamic channel `name`.
#[derive(Debug)]
pub struct SvcOverDvc<P> {
    name: &'static str,
    inner: P,
}

impl<P> SvcOverDvc<P> {
    pub fn new(name: &'static str, inner: P) -> Self {
        Self { name, inner }
    }
}

/// An already-encoded PDU, sent unchanged.
struct Raw(Vec<u8>);

impl Encode for Raw {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ironrdp_core::ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SvcOverDvc"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl DvcEncode for Raw {}

fn to_dvc(messages: Vec<SvcMessage>) -> PduResult<Vec<DvcMessage>> {
    messages
        .into_iter()
        .map(|m| {
            let bytes = m.encode_unframed_pdu().map_err(|e| ironrdp_pdu::pdu_other_err!("svc over dvc", source: e))?;
            Ok(Box::new(Raw(bytes)) as DvcMessage)
        })
        .collect()
}

impl<P: SvcProcessor + 'static> DvcProcessor for SvcOverDvc<P> {
    fn channel_name(&self) -> &str {
        self.name
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        to_dvc(self.inner.start()?)
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        to_dvc(self.inner.process(payload)?)
    }
}

impl<P: SvcProcessor + 'static> DvcClientProcessor for SvcOverDvc<P> {}

impl<P: 'static> ironrdp_core::AsAny for SvcOverDvc<P> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers every PDU with "ack:" + the PDU, and greets on start.
    #[derive(Debug)]
    struct Echo;
    ironrdp_core::impl_as_any!(Echo);

    impl SvcProcessor for Echo {
        fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
            ironrdp_pdu::gcc::ChannelName::from_static(b"echo\0\0\0\0")
        }
        fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
            Ok(vec![SvcMessage::from(Raw(b"hello".to_vec()))])
        }
        fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
            Ok(vec![SvcMessage::from(Raw([b"ack:".as_slice(), payload].concat()))])
        }
    }

    impl ironrdp_svc::SvcEncode for Raw {}

    fn bytes(m: &DvcMessage) -> Vec<u8> {
        ironrdp_core::encode_vec(m.as_ref()).unwrap()
    }

    #[test]
    fn forwards_pdus_unchanged_both_ways() {
        let mut c = SvcOverDvc::new("rdpdr", Echo);
        assert_eq!(c.channel_name(), "rdpdr");
        let start = c.start(14).unwrap();
        assert_eq!(start.iter().map(bytes).collect::<Vec<_>>(), vec![b"hello".to_vec()]);
        let out = c.process(14, b"\x72\x44\x6e\x49").unwrap();
        assert_eq!(out.iter().map(bytes).collect::<Vec<_>>(), vec![b"ack:\x72\x44\x6e\x49".to_vec()]);
    }

    #[test]
    fn the_device_redirection_handler_answers_a_server_announce_on_the_dynamic_channel() {
        // Server Announce Request (MS-RDPEFS 2.2.2.2): RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE,
        // version 1.13, client ID 7. The handler must reply with Client Announce Reply and Client
        // Name Request, exactly as on the static channel.
        let rdpdr = ironrdp_rdpdr::Rdpdr::new(Box::new(ironrdp_rdpdr::NoopRdpdrBackend), "laptop".into());
        let mut c = SvcOverDvc::new("rdpdr", rdpdr);
        let _ = c.start(14).unwrap();
        let announce = [0x72, 0x44, 0x6e, 0x49, 0x01, 0x00, 0x0d, 0x00, 0x07, 0x00, 0x00, 0x00];
        let out: Vec<Vec<u8>> = c.process(14, &announce).unwrap().iter().map(bytes).collect();
        assert!(out.len() >= 2, "{out:?}");
        // Client Announce Reply: core, PAKID_CORE_CLIENTID_CONFIRM ("CC"), echoing client ID 7.
        assert_eq!(&out[0][..4], &[0x72, 0x44, 0x43, 0x43]);
        assert_eq!(&out[0][8..12], &[0x07, 0, 0, 0]);
        // Client Name Request: PAKID_CORE_CLIENT_NAME ("NC").
        assert_eq!(&out[1][..4], &[0x72, 0x44, 0x4e, 0x43]);
    }
}
