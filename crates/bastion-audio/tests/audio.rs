use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use bastion_audio::playback::{client_formats, is_playable};
use bastion_audio::{
    AudioHost, CaptureDevice, CaptureOptions, PcmSpec, PlaybackDevice, PlaybackOptions, PulseCapture, PulsePlayback,
};
use ironrdp_rdpeai::client::RdpeaiCaptureHandler as _;
use ironrdp_rdpeai::pdu::{OpenReplyPdu, pcm_format};
use ironrdp_rdpsnd::client::RdpsndClientHandler as _;
use ironrdp_rdpsnd::codec::ima_adpcm_format;
use ironrdp_rdpsnd::pdu::{AudioFormat, VolumePdu, WaveFormat};

#[derive(Default)]
struct Log {
    opened: Vec<(Option<String>, PcmSpec)>,
    written: Vec<i16>,
}

#[derive(Clone, Default)]
struct MockHost {
    log: Arc<Mutex<Log>>,
    write_delay: Duration,
    fail_capture: bool,
}

struct MockOut(Arc<Mutex<Log>>, Duration);
impl PlaybackDevice for MockOut {
    fn write(&mut self, s: &[i16]) -> Result<()> {
        std::thread::sleep(self.1);
        self.0.lock().unwrap().written.extend_from_slice(s);
        Ok(())
    }
    fn latency(&self) -> Duration {
        Duration::from_millis(5)
    }
}

/// Produces a ramp so tests can check bytes flow through unchanged.
struct MockIn(u8);
impl CaptureDevice for MockIn {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        std::thread::sleep(Duration::from_millis(2));
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl AudioHost for MockHost {
    fn open_playback(&self, device: Option<&str>, spec: PcmSpec, _l: Duration) -> Result<Box<dyn PlaybackDevice>> {
        self.log.lock().unwrap().opened.push((device.map(str::to_owned), spec));
        Ok(Box::new(MockOut(self.log.clone(), self.write_delay)))
    }
    fn open_capture(&self, _d: Option<&str>, _s: PcmSpec, _f: usize) -> Result<Box<dyn CaptureDevice>> {
        if self.fail_capture {
            anyhow::bail!("no microphone");
        }
        Ok(Box::new(MockIn(0)))
    }
}

fn pcm(ch: u16, rate: u32) -> AudioFormat {
    pcm_format(ch, rate, 16)
}

fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn bytes(samples: &[i16]) -> Vec<u8> {
    samples.iter().flat_map(|s| s.to_le_bytes()).collect()
}

#[test]
fn negotiation_keeps_only_decodable_formats_in_server_order() {
    let p = PulsePlayback::with_host(Arc::new(MockHost::default()), PlaybackOptions::default());
    let aac = AudioFormat { format: WaveFormat::AAC_MS, ..pcm(2, 44_100) };
    let six_ch = pcm(6, 48_000);
    let adpcm = ima_adpcm_format(2, 22_050, 2048);
    let chosen = p.choose_formats(&[aac, pcm(2, 48_000), six_ch, adpcm.clone()]);
    assert_eq!(chosen, vec![pcm(2, 48_000), adpcm]);
    assert!(client_formats().iter().all(is_playable));
}

#[test]
fn pcm_wave_reaches_device_bit_exact() {
    let host = MockHost::default();
    let mut p = PulsePlayback::with_host(
        Arc::new(host.clone()),
        PlaybackOptions { device: Some("headset".into()), ..Default::default() },
    );
    let samples: Vec<i16> = (0..4410).map(|i| (i * 7) as i16).collect();
    p.wave(&pcm(2, 44_100), 0, Cow::Owned(bytes(&samples)));
    wait_until(|| host.log.lock().unwrap().written.len() == samples.len());
    let log = host.log.lock().unwrap();
    assert_eq!(log.written, samples);
    assert_eq!(log.opened, vec![(Some("headset".into()), PcmSpec { rate: 44_100, channels: 2 })]);
}

#[test]
fn server_volume_is_applied_per_channel() {
    let host = MockHost::default();
    let mut p = PulsePlayback::with_host(Arc::new(host.clone()), PlaybackOptions::default());
    p.set_volume(VolumePdu { volume_left: 65535, volume_right: 0 });
    p.wave(&pcm(2, 48_000), 0, Cow::Owned(bytes(&[1000, 1000, -2000, -2000])));
    wait_until(|| host.log.lock().unwrap().written.len() == 4);
    assert_eq!(host.log.lock().unwrap().written, vec![1000, 0, -2000, 0]);
}

#[test]
fn format_change_reopens_device_with_new_spec() {
    let host = MockHost::default();
    let mut p = PulsePlayback::with_host(Arc::new(host.clone()), PlaybackOptions::default());
    p.wave(&pcm(2, 44_100), 0, Cow::Owned(bytes(&[1, 2])));
    wait_until(|| host.log.lock().unwrap().written.len() == 2);
    p.wave(&pcm(1, 22_050), 0, Cow::Owned(bytes(&[3])));
    wait_until(|| host.log.lock().unwrap().written.len() == 3);
    let specs: Vec<_> = host.log.lock().unwrap().opened.iter().map(|o| o.1).collect();
    assert_eq!(specs, vec![PcmSpec { rate: 44_100, channels: 2 }, PcmSpec { rate: 22_050, channels: 1 }]);
}

#[test]
fn latency_stays_bounded_when_device_is_slow() {
    // Device consumes far slower than real time; the player must drop rather than queue forever.
    let host = MockHost { write_delay: Duration::from_millis(30), ..Default::default() };
    let opts = PlaybackOptions { latency: Duration::from_millis(40), ..Default::default() };
    let mut p = PulsePlayback::with_host(Arc::new(host.clone()), opts);
    let chunk = bytes(&vec![0i16; 882 * 2]); // 20 ms at 44.1 kHz stereo
    for _ in 0..100 {
        p.wave(&pcm(2, 44_100), 0, Cow::Borrowed(&chunk));
    }
    assert!(p.playback_latency() < Duration::from_secs(3));
    p.close(); // must not hang
    let written = host.log.lock().unwrap().written.len();
    assert!(written < 100 * 882 * 2, "late audio should have been dropped");
}

#[test]
fn microphone_pcm_packets_have_requested_size() {
    let mut c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let g = got.clone();
    let rc = c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(move |p| g.lock().unwrap().push(p)));
    assert_eq!(rc, OpenReplyPdu::S_OK);
    wait_until(|| got.lock().unwrap().len() >= 3);
    c.close();
    let packets = got.lock().unwrap();
    assert!(packets.iter().all(|p| p.len() == 640));
    assert_eq!(packets[0][..4], [0, 1, 2, 3]);
}

#[test]
fn microphone_adpcm_encoding_and_format_switch() {
    let mut c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
    let adpcm = ima_adpcm_format(1, 16_000, 512);
    assert_eq!(c.choose_formats(&[adpcm.clone(), pcm(6, 16_000)]), vec![adpcm.clone()]);
    let got: Arc<Mutex<Vec<usize>>> = Arc::default();
    let g = got.clone();
    let packet = 1017 * 2; // one IMA block of PCM input (1017 frames mono)
    assert_eq!(
        c.open(&pcm(1, 16_000), &adpcm, packet, Box::new(move |p| g.lock().unwrap().push(p.len()))),
        OpenReplyPdu::S_OK
    );
    wait_until(|| !got.lock().unwrap().is_empty());
    assert!(got.lock().unwrap()[0] < packet, "ADPCM output should be compressed");
    assert!(c.set_format(&pcm(1, 16_000), packet));
    // A rate/channel change restarts capture in the new format instead of failing the mic.
    assert!(c.set_format(&pcm(2, 44_100), packet), "format change with new rate must be accepted");
    c.close();
}

#[test]
fn microphone_open_failure_reports_e_fail() {
    let mut c = PulseCapture::with_host(
        Arc::new(MockHost { fail_capture: true, ..Default::default() }),
        CaptureOptions::default(),
    );
    assert_eq!(c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(|_| {})), OpenReplyPdu::E_FAIL);
}

/// Exercises the real sound server when one is running (PipeWire/PulseAudio); otherwise skipped.
#[test]
fn real_sound_server_smoke() {
    let Ok(list) = bastion_audio::list_devices() else {
        eprintln!("no sound server; skipping");
        return;
    };
    eprintln!("outputs: {:?}", list.outputs.iter().map(|d| &d.description).collect::<Vec<_>>());
    eprintln!("inputs: {:?}", list.inputs.iter().map(|d| &d.description).collect::<Vec<_>>());
    assert!(list.outputs.iter().filter(|d| d.is_default).count() <= 1);
    let host = bastion_audio::PulseHost;
    let spec = PcmSpec { rate: 48_000, channels: 2 };
    let mut out = host.open_playback(None, spec, Duration::from_millis(50)).expect("default output opens");
    out.write(&vec![0i16; 960]).unwrap(); // 10 ms of silence
    if !list.inputs.is_empty() {
        let mut mic = host.open_capture(None, PcmSpec { rate: 16_000, channels: 1 }, 320).expect("default mic opens");
        let mut buf = vec![0u8; 320];
        mic.read(&mut buf).unwrap();
    }
}

#[test]
fn windows_extensible_pcm_is_played_and_captured() {
    // WAVE_FORMAT_EXTENSIBLE + PCM sub-format, as sent by Windows 10/11.
    let mut data = vec![16u8, 0, 3, 0, 0, 0];
    data.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xAA, 0, 0x38, 0x9B, 0x71]);
    let ext = AudioFormat { format: WaveFormat::EXTENSIBLE, data: Some(data), ..pcm(2, 44_100) };

    let host = MockHost::default();
    let mut p = PulsePlayback::with_host(Arc::new(host.clone()), PlaybackOptions::default());
    assert_eq!(p.choose_formats(std::slice::from_ref(&ext)).len(), 1);
    p.wave(&ext, 0, Cow::Owned(bytes(&[5, -5, 7, -7])));
    wait_until(|| host.log.lock().unwrap().written.len() == 4);

    let mut c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
    assert_eq!(c.choose_formats(std::slice::from_ref(&ext)).len(), 1);
    let got: Arc<Mutex<usize>> = Arc::default();
    let g = got.clone();
    assert_eq!(c.open(&ext, &ext, 1764, Box::new(move |p| *g.lock().unwrap() += p.len())), OpenReplyPdu::S_OK);
    wait_until(|| *got.lock().unwrap() >= 1764);
    c.close();
}

#[test]
fn microphone_keeps_streaming_after_server_switches_rate() {
    let mut c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
    let sizes: Arc<Mutex<Vec<usize>>> = Arc::default();
    let s = sizes.clone();
    assert_eq!(
        c.open(&pcm(1, 16_000), &pcm(1, 16_000), 320, Box::new(move |p| s.lock().unwrap().push(p.len()))),
        OpenReplyPdu::S_OK
    );
    wait_until(|| !sizes.lock().unwrap().is_empty());
    assert!(c.set_format(&pcm(2, 44_100), 320));
    sizes.lock().unwrap().clear();
    wait_until(|| sizes.lock().unwrap().len() >= 2);
    // 10 ms packets are preserved: 441 frames at 44.1 kHz * 2ch * 2 bytes.
    assert!(sizes.lock().unwrap().iter().all(|&n| n == 1764), "{:?}", sizes.lock().unwrap());
    c.close();
}

/// Exactly what the user's Windows PC requested: capture 44.1 kHz stereo PCM, encode MS-ADPCM
/// 22.05 kHz mono. The device must be opened in the encode shape, not the capture shape.
#[derive(Clone, Default)]
struct SpecRecorder(Arc<Mutex<Vec<(PcmSpec, usize)>>>);

impl AudioHost for SpecRecorder {
    fn open_playback(&self, _: Option<&str>, _: PcmSpec, _: Duration) -> Result<Box<dyn PlaybackDevice>> {
        anyhow::bail!("unused")
    }
    fn open_capture(&self, _: Option<&str>, spec: PcmSpec, frag: usize) -> Result<Box<dyn CaptureDevice>> {
        self.0.lock().unwrap().push((spec, frag));
        Ok(Box::new(MockIn(0)))
    }
}

#[test]
fn windows_adpcm_mic_is_recorded_in_the_encode_shape() {
    let host = SpecRecorder::default();
    let mut c = PulseCapture::with_host(Arc::new(host.clone()), CaptureOptions::default());
    let adpcm = ironrdp_rdpsnd::codec::ms_adpcm_format(1, 22_050, 512);
    let got: Arc<Mutex<Vec<usize>>> = Arc::default();
    let g = got.clone();
    assert_eq!(
        c.open(&pcm(2, 44_100), &adpcm, 1764, Box::new(move |p| g.lock().unwrap().push(p.len()))),
        OpenReplyPdu::S_OK
    );
    assert_eq!(host.0.lock().unwrap()[0], (PcmSpec { rate: 22_050, channels: 1 }, 440));
    wait_until(|| !got.lock().unwrap().is_empty());
    // Every packet is a whole number of 512-byte ADPCM blocks.
    assert!(got.lock().unwrap().iter().all(|&n| n % 512 == 0), "{:?}", got.lock().unwrap());
    c.close();
}

#[test]
fn packet_rescaling_preserves_duration() {
    use bastion_audio::capture::rescale_packet;
    let s = |rate, channels| PcmSpec { rate, channels };
    assert_eq!(rescale_packet(1764, s(44_100, 2), s(22_050, 1)), 440);
    assert_eq!(rescale_packet(320, s(16_000, 1), s(44_100, 2)), 1764);
}
