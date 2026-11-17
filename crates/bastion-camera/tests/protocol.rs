//! Drives Bastion's camera channels through the MS-RDPECAM message flow a Windows server uses,
//! with an in-memory camera standing in for V4L2.

use std::sync::{Arc, Mutex};

use bastion_camera::{CameraHost, CameraInfo, FrameCallback, Mode, PixelFormat, RunningCapture, camera_channels};
use ironrdp_core::{decode, encode_vec};
use ironrdp_dvc::{DvcChannelListener as _, DvcClientProcessor, DvcMessage, DvcProcessor as _};
use ironrdp_rdpecam::pdu::{DeviceMessage, DevicePdu, EnumerationPdu};
use ironrdp_rdpecam::{MediaFormat, ProtocolVersion, SampleUplink, StartStreamInfo};
use ironrdp_svc::SvcMessage;

const V2: ProtocolVersion = ProtocolVersion::V2;

#[derive(Default)]
struct FakeState {
    on_frame: Option<FrameCallback>,
    started: Vec<Mode>,
}

#[derive(Clone, Default)]
struct FakeHost {
    cameras: Vec<CameraInfo>,
    state: Arc<Mutex<FakeState>>,
}

struct FakeCapture(Arc<Mutex<FakeState>>);
impl RunningCapture for FakeCapture {}
impl Drop for FakeCapture {
    fn drop(&mut self) {
        self.0.lock().unwrap().on_frame = None;
    }
}

impl CameraHost for FakeHost {
    fn cameras(&self) -> Vec<CameraInfo> {
        self.cameras.clone()
    }
    fn start(&self, _: &CameraInfo, mode: Mode, on_frame: FrameCallback) -> anyhow::Result<Box<dyn RunningCapture>> {
        let mut s = self.state.lock().unwrap();
        s.on_frame = Some(on_frame);
        s.started.push(mode);
        Ok(Box::new(FakeCapture(self.state.clone())))
    }
}

impl FakeHost {
    fn emit(&self, frame: &[u8]) {
        let mut s = self.state.lock().unwrap();
        (s.on_frame.as_mut().expect("camera not running"))(frame);
    }
    fn running(&self) -> bool {
        self.state.lock().unwrap().on_frame.is_some()
    }
}

fn mode(format: PixelFormat, width: u32, height: u32, fps: u32) -> Mode {
    Mode { format, width, height, fps_num: fps, fps_den: 1 }
}

fn brio() -> CameraInfo {
    CameraInfo {
        id: "/dev/video0".into(),
        name: "Logitech BRIO".into(),
        modes: vec![
            mode(PixelFormat::Yuyv, 640, 480, 30),
            mode(PixelFormat::Mjpeg, 640, 480, 30),
            mode(PixelFormat::Mjpeg, 1280, 720, 30),
        ],
    }
}

fn ir_sensor() -> CameraInfo {
    // Greyscale-only nodes never reach here (the V4L2 host filters them); a camera whose only
    // modes are too large for raw transfer has nothing to offer and must not be advertised.
    CameraInfo { id: "/dev/video2".into(), name: "IR".into(), modes: vec![mode(PixelFormat::Yuyv, 1920, 1080, 30)] }
}

type Uplinked = Arc<Mutex<Vec<(u32, Vec<SvcMessage>)>>>;

fn uplink() -> (SampleUplink, Uplinked) {
    let sent: Uplinked = Arc::default();
    let s = sent.clone();
    let up: SampleUplink = Arc::new(move |id, msgs| {
        s.lock().unwrap().push((id, msgs));
        Ok(())
    });
    (up, sent)
}

fn device_replies(out: Vec<DvcMessage>) -> Vec<DevicePdu> {
    out.iter().map(|m| decode::<DeviceMessage>(&encode_vec(m.as_ref()).unwrap()).unwrap().pdu).collect()
}

fn send(dev: &mut Box<dyn DvcClientProcessor>, id: u32, pdu: DevicePdu) -> Vec<DevicePdu> {
    let bytes = encode_vec(&DeviceMessage::new(V2, pdu)).unwrap();
    device_replies(dev.process(id, &bytes).unwrap())
}

/// The sample carried by an uplinked DRDYNVC data PDU (its payload is the trailing bytes).
fn uplinked_samples(sent: &Uplinked) -> Vec<Vec<u8>> {
    sent.lock()
        .unwrap()
        .drain(..)
        .flat_map(|(_, msgs)| msgs)
        .map(|m| {
            let bytes = m.encode_unframed_pdu().unwrap();
            // DRDYNVC data header (1 cmd byte + 1-byte channel id here) then the RDPECAM message.
            match decode::<DeviceMessage>(&bytes[2..]).unwrap().pdu {
                DevicePdu::SampleResponse { stream_index: 0, sample } => sample,
                other => panic!("expected a sample, got {other:?}"),
            }
        })
        .collect()
}

#[test]
fn no_usable_camera_means_no_channels() {
    let host = FakeHost { cameras: vec![ir_sensor()], ..Default::default() };
    assert!(camera_channels(Arc::new(host), uplink().0).is_none());
}

#[test]
fn full_camera_session_streams_mjpeg_frames() {
    let host = FakeHost { cameras: vec![brio(), ir_sensor()], ..Default::default() };
    let (up, sent) = uplink();
    let mut ch = camera_channels(Arc::new(host.clone()), up).expect("camera channels");
    let mut enumerator = ch.enumerator();
    assert_eq!(ch.names, ["Logitech BRIO"]);
    assert_eq!(ch.devices.len(), 1);

    // Enumeration channel: version negotiation, then the device announcement.
    let enum_id = 3;
    let out = enumerator.start(enum_id).unwrap();
    let first = decode::<EnumerationPdu>(&encode_vec(out[0].as_ref()).unwrap()).unwrap();
    assert!(matches!(first, EnumerationPdu::SelectVersionRequest(ProtocolVersion::V2)), "{first:?}");
    let reply = encode_vec(&EnumerationPdu::SelectVersionResponse(V2)).unwrap();
    let out = enumerator.process(enum_id, &reply).unwrap();
    let added: Vec<_> =
        out.iter().map(|m| decode::<EnumerationPdu>(&encode_vec(m.as_ref()).unwrap()).unwrap()).collect();
    let [EnumerationPdu::DeviceAdded { device, .. }] = &added[..] else { panic!("expected one device: {added:?}") };
    assert_eq!(device.display_name, "Logitech BRIO");
    assert_eq!(device.channel_name, "RDCamera_Device_0");

    // The server opens the device channel by that name.
    let listener = &mut ch.devices[0];
    assert_eq!(listener.channel_name(), "RDCamera_Device_0");
    let dev_id = 4;
    let mut dev = listener.create(dev_id).expect("device channel accepted");
    dev.start(dev_id).unwrap();

    assert!(matches!(send(&mut dev, dev_id, DevicePdu::ActivateDeviceRequest)[..], [DevicePdu::SuccessResponse]));
    let streams = send(&mut dev, dev_id, DevicePdu::StreamListRequest);
    assert!(matches!(&streams[..], [DevicePdu::StreamListResponse(s)] if s.len() == 1), "{streams:?}");

    // Only MJPG is offered (the camera has it), 720p first; the raw YUYV mode is withheld.
    let types = match &send(&mut dev, dev_id, DevicePdu::MediaTypeListRequest(0))[..] {
        [DevicePdu::MediaTypeListResponse(t)] => t.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        types.iter().map(|t| (t.format, t.width, t.height)).collect::<Vec<_>>(),
        [(MediaFormat::Mjpg, 1280, 720), (MediaFormat::Mjpg, 640, 480)]
    );
    let current = send(&mut dev, dev_id, DevicePdu::CurrentMediaTypeRequest(0));
    assert!(matches!(&current[..], [DevicePdu::CurrentMediaTypeResponse(t)] if *t == types[0]));

    // Windows picks 640×480.
    let start = DevicePdu::StartStreamsRequest(vec![StartStreamInfo { stream_index: 0, media_type: types[1] }]);
    assert!(matches!(send(&mut dev, dev_id, start)[..], [DevicePdu::SuccessResponse]));
    assert_eq!(host.state.lock().unwrap().started, [mode(PixelFormat::Mjpeg, 640, 480, 30)]);

    // A frame captured before the server asks is held, then sent on the request.
    let jpeg1 = [0xFF, 0xD8, 1, 2, 3, 0xFF, 0xD9];
    host.emit(&jpeg1);
    assert!(uplinked_samples(&sent).is_empty());
    assert!(send(&mut dev, dev_id, DevicePdu::SampleRequest(0)).is_empty());
    assert_eq!(uplinked_samples(&sent), [jpeg1.to_vec()]);

    // With a request outstanding, the next frame goes straight out; only the newest unrequested
    // frame is kept.
    assert!(send(&mut dev, dev_id, DevicePdu::SampleRequest(0)).is_empty());
    let jpeg2 = [0xFF, 0xD8, 4, 0xFF, 0xD9];
    host.emit(&jpeg2);
    let (old, new) = ([0xFF, 0xD8, 5, 0xFF, 0xD9], [0xFF, 0xD8, 6, 0xFF, 0xD9]);
    host.emit(&old);
    host.emit(&new);
    assert!(send(&mut dev, dev_id, DevicePdu::SampleRequest(0)).is_empty());
    assert_eq!(uplinked_samples(&sent), [jpeg2.to_vec(), new.to_vec()]);

    // Stopping releases the camera.
    assert!(matches!(send(&mut dev, dev_id, DevicePdu::StopStreamsRequest)[..], [DevicePdu::SuccessResponse]));
    assert!(!host.running(), "camera must be released when the remote stops streaming");
}

#[test]
fn closing_the_channel_releases_the_camera() {
    let host = FakeHost { cameras: vec![brio()], ..Default::default() };
    let (up, _sent) = uplink();
    let mut ch = camera_channels(Arc::new(host.clone()), up).unwrap();
    let mut enumerator = ch.enumerator();
    let reply = encode_vec(&EnumerationPdu::SelectVersionResponse(V2)).unwrap();
    enumerator.start(1).unwrap();
    enumerator.process(1, &reply).unwrap();
    let mut dev = ch.devices[0].create(2).unwrap();
    dev.start(2).unwrap();
    send(&mut dev, 2, DevicePdu::ActivateDeviceRequest);
    let types = match &send(&mut dev, 2, DevicePdu::MediaTypeListRequest(0))[..] {
        [DevicePdu::MediaTypeListResponse(t)] => t.clone(),
        other => panic!("{other:?}"),
    };
    send(&mut dev, 2, DevicePdu::StartStreamsRequest(vec![StartStreamInfo { stream_index: 0, media_type: types[0] }]));
    assert!(host.running());
    dev.close(2);
    assert!(!host.running(), "camera must be released when the channel closes (e.g. disconnect)");
}

/// What Windows actually does: open the camera list during logon, close every dynamic channel
/// when it hands over to the user's desktop, then open them again. The second open must succeed.
#[test]
fn enumeration_channel_can_be_reopened_after_windows_closes_it() {
    use ironrdp_dvc::pdu::{
        CapabilitiesRequestPdu, CapsVersion, ClosePdu, CreateRequestPdu, CreationStatus, DrdynvcClientPdu,
        DrdynvcServerPdu,
    };
    use ironrdp_svc::SvcProcessor as _;

    let host = FakeHost { cameras: vec![brio()], ..Default::default() };
    let mut drdynvc = camera_channels(Arc::new(host), uplink().0).unwrap().register(ironrdp_dvc::DrdynvcClient::new());

    let mut server = |pdu: DrdynvcServerPdu| -> Vec<DrdynvcClientPdu> {
        drdynvc
            .process(&encode_vec(&pdu).unwrap())
            .unwrap()
            .iter()
            .map(|m| decode::<DrdynvcClientPdu>(&m.encode_unframed_pdu().unwrap()).unwrap())
            .collect()
    };
    let created = |replies: &[DrdynvcClientPdu]| {
        replies.iter().find_map(|r| match r {
            DrdynvcClientPdu::Create(c) => Some(c.creation_status()),
            _ => None,
        })
    };

    server(DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V3, None)));
    for (round, id) in [(1, 18), (2, 17)] {
        let open =
            DrdynvcServerPdu::Create(CreateRequestPdu::new(id, ironrdp_rdpecam::ENUMERATION_CHANNEL_NAME.into()));
        assert_eq!(created(&server(open)), Some(CreationStatus::OK), "camera list open #{round} refused");
        server(DrdynvcServerPdu::Close(ClosePdu::new(id)));
    }
}
