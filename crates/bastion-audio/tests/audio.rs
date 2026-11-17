use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use bastion_audio::playback::{client_formats, is_playable};
use bastion_audio::{
    AudioHost, CaptureDevice, CaptureOptions, MicThreads, PcmSpec, PlaybackDevice, PlaybackOptions, PulseCapture,
    PulsePlayback,
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

// ---- Hostile servers -------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bastion_audio::capture::{MAX_PACKET_BYTES, checked_rescale_packet, is_capturable, rescale_packet};
use ironrdp_rdpsnd::codec::alaw_format;

/// A microphone that delivers audio in real time (a read takes as long as the audio it returns),
/// or, while `stuck` is set, not at all.
#[derive(Clone, Default)]
struct RealTimeHost {
    opened: Arc<Mutex<Vec<(PcmSpec, usize)>>>,
    stuck: Arc<AtomicBool>,
}

struct RealTimeIn(PcmSpec, Arc<AtomicBool>);
impl CaptureDevice for RealTimeIn {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.1.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let bytes_per_sec = u64::from(self.0.rate) * self.0.bytes_per_frame() as u64;
        std::thread::sleep(Duration::from_micros(buf.len() as u64 * 1_000_000 / bytes_per_sec.max(1)));
        buf.fill(0);
        Ok(())
    }
}

impl AudioHost for RealTimeHost {
    fn open_playback(&self, _: Option<&str>, _: PcmSpec, _: Duration) -> Result<Box<dyn PlaybackDevice>> {
        anyhow::bail!("unused")
    }
    fn open_capture(&self, _: Option<&str>, spec: PcmSpec, frag: usize) -> Result<Box<dyn CaptureDevice>> {
        self.opened.lock().unwrap().push((spec, frag));
        Ok(Box::new(RealTimeIn(spec, self.stuck.clone())))
    }
}

/// The Open PDU's capture WAVEFORMATEX is not negotiated; a server can put anything in it.
#[test]
fn hostile_capture_formats_are_refused_before_anything_is_opened_or_allocated() {
    let host = RealTimeHost::default();
    let mut c = PulseCapture::with_host(Arc::new(host.clone()), CaptureOptions::default());
    let alaw = alaw_format(2, 48_000);
    assert!(is_capturable(&alaw));

    // The audited case: 256 channels (0 after truncation to u8) at 0 Hz with a compressed encode
    // format used to rescale a 192 kB packet into a ~37 GB buffer.
    let evil = |channels: u16, rate: u32| AudioFormat {
        format: WaveFormat::PCM,
        n_channels: channels,
        n_samples_per_sec: rate,
        n_avg_bytes_per_sec: 0,
        n_block_align: channels.wrapping_mul(2),
        bits_per_sample: 16,
        data: None,
    };
    for (channels, rate, packet) in [
        (256, 0, 192_000),
        (0xFF00, 0, 130_560),
        (0, 48_000, 1920),
        (2, 0, 1920),
        (2, 1, 192_000),
        (2, 1_000, 192_000),
        (9, 48_000, 1920),
        (2, u32::MAX, 1920),
    ] {
        for encode in [&alaw, &pcm(2, 48_000)] {
            let rc = c.open(&evil(channels, rate), encode, packet, Box::new(|_| {}));
            assert_eq!(rc, OpenReplyPdu::E_FAIL, "{channels} ch / {rate} Hz must be refused");
        }
    }
    // Sizes outside what MS-RDPEAI allows, and a block alignment that contradicts the layout.
    assert_eq!(c.open(&pcm(2, 48_000), &pcm(2, 48_000), 0, Box::new(|_| {})), OpenReplyPdu::E_FAIL);
    assert_eq!(c.open(&pcm(2, 48_000), &pcm(2, 48_000), MAX_PACKET_BYTES + 4, Box::new(|_| {})), OpenReplyPdu::E_FAIL);
    assert_eq!(c.open(&pcm(2, 48_000), &alaw, usize::MAX, Box::new(|_| {})), OpenReplyPdu::E_FAIL);
    let misaligned = AudioFormat { n_block_align: 0, ..pcm(2, 48_000) };
    assert_eq!(c.open(&misaligned, &pcm(2, 48_000), 1920, Box::new(|_| {})), OpenReplyPdu::E_FAIL);
    // A valid shape whose rescaled packet would exceed the cap: 1 s of 8 kHz mono → 48 kHz stereo is
    // fine (exactly the cap), 2 s is not.
    assert_eq!(c.open(&pcm(1, 8_000), &alaw, 32_000, Box::new(|_| {})), OpenReplyPdu::E_FAIL);

    assert!(host.opened.lock().unwrap().is_empty(), "no device may be opened for a refused format");

    // The same handler still works for a sane request afterwards.
    assert_eq!(c.open(&pcm(1, 8_000), &alaw, 16_000, Box::new(|_| {})), OpenReplyPdu::S_OK);
    c.close();
    assert_eq!(host.opened.lock().unwrap()[0].0, PcmSpec { rate: 48_000, channels: 2 });
}

#[test]
fn packet_rescaling_is_checked_and_bounded() {
    let s = |rate, channels| PcmSpec { rate, channels };
    // Degenerate shapes used to divide by a clamped 1 and multiply the size by the target rate.
    assert_eq!(checked_rescale_packet(192_000, s(0, 0), s(48_000, 2)), None);
    assert_eq!(checked_rescale_packet(192_000, s(0, 2), s(48_000, 2)), None);
    assert_eq!(checked_rescale_packet(192_000, s(48_000, 2), s(0, 2)), None);
    assert_eq!(checked_rescale_packet(192_000, s(48_000, 2), s(48_000, 0)), None);
    assert_eq!(checked_rescale_packet(usize::MAX, s(1, 1), s(u32::MAX, 255)), None);
    assert_eq!(checked_rescale_packet(192_000, s(8_000, 1), s(48_000, 2)), None);
    // Legitimate conversions are unchanged, up to exactly the cap.
    assert_eq!(checked_rescale_packet(1764, s(44_100, 2), s(22_050, 1)), Some(440));
    assert_eq!(checked_rescale_packet(16_000, s(8_000, 1), s(48_000, 2)), Some(MAX_PACKET_BYTES));
    // The infallible variant never overflows and never exceeds the cap.
    for (bytes, from, to) in [
        (192_000, s(0, 0), s(48_000, 2)),
        (usize::MAX, s(1, 1), s(u32::MAX, 255)),
        (usize::MAX, s(0, 0), s(u32::MAX, 3)),
        (192_000, s(8_000, 1), s(192_000, 8)),
    ] {
        let n = rescale_packet(bytes, from, to);
        assert!(n <= MAX_PACKET_BYTES, "{n}");
        assert_eq!(n % to.bytes_per_frame(), 0);
    }
    assert_eq!(rescale_packet(1000, s(48_000, 2), s(48_000, 0)), 0);
}

#[test]
fn format_change_cannot_inflate_the_packet_size() {
    let host = RealTimeHost::default();
    let mut c = PulseCapture::with_host(Arc::new(host.clone()), CaptureOptions::default());
    // 3 s packets of 8 kHz mono are within the Open limits (48 000 frames)…
    assert_eq!(c.open(&pcm(1, 8_000), &pcm(1, 8_000), 48_000, Box::new(|_| {})), OpenReplyPdu::S_OK);
    // …but the same duration at 48 kHz stereo would be 576 kB per packet.
    assert!(!c.set_format(&pcm(2, 48_000), 48_000), "oversized packet after a format change must be refused");
    // Formats that never went through negotiation are refused too.
    assert!(!c.set_format(&AudioFormat { n_channels: 256, ..pcm(2, 48_000) }, 48_000));
    assert!(!c.set_format(&AudioFormat { n_samples_per_sec: 0, ..pcm(2, 48_000) }, 48_000));
    c.close();
    assert!(host.opened.lock().unwrap().iter().all(|(_, frag)| *frag <= MAX_PACKET_BYTES));
    assert_eq!(host.opened.lock().unwrap().len(), 1, "refused format changes must not reopen the device");
}

#[test]
fn negotiation_refuses_formats_with_inconsistent_parameters() {
    let p = PulsePlayback::with_host(Arc::new(MockHost::default()), PlaybackOptions::default());
    let c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
    let bad = [
        AudioFormat { n_block_align: 0, ..pcm(2, 44_100) },
        AudioFormat { n_block_align: 3, ..pcm(2, 44_100) },
        AudioFormat { n_block_align: 0, ..alaw_format(1, 8_000) },
        AudioFormat { n_samples_per_sec: 0, ..pcm(2, 44_100) },
        AudioFormat { n_channels: 0, ..pcm(2, 44_100) },
        AudioFormat { n_channels: 258, ..pcm(2, 44_100) },
        AudioFormat { bits_per_sample: 24, n_block_align: 6, ..pcm(2, 44_100) },
    ];
    assert!(p.choose_formats(&bad).is_empty());
    assert!(c.choose_formats(&bad).is_empty());
    // …while the usual ones still pass, in server order.
    let good = [pcm(2, 44_100), alaw_format(1, 8_000), ima_adpcm_format(2, 22_050, 2048)];
    assert_eq!(p.choose_formats(&good), good);
    assert_eq!(c.choose_formats(&good), good);
}

#[test]
fn wave_in_an_unvalidated_format_is_dropped_without_opening_a_device() {
    let host = MockHost::default();
    let mut p = PulsePlayback::with_host(Arc::new(host.clone()), PlaybackOptions::default());
    for f in [
        AudioFormat { n_channels: 256, n_block_align: 512, ..pcm(2, 44_100) }, // truncates to 0 channels
        AudioFormat { n_channels: 6, n_block_align: 12, ..pcm(2, 44_100) },
        AudioFormat { n_samples_per_sec: 1, ..pcm(2, 44_100) },
        AudioFormat { n_samples_per_sec: u32::MAX, ..pcm(2, 44_100) },
        AudioFormat { n_block_align: 0, ..pcm(2, 44_100) },
    ] {
        p.wave(&f, 0, Cow::Owned(bytes(&[1, 2, 3, 4])));
    }
    assert_eq!(p.playback_latency(), Duration::ZERO);
    // A good wave afterwards plays, and it is the only thing that ever reached a device.
    p.wave(&pcm(2, 44_100), 0, Cow::Owned(bytes(&[9, 8])));
    wait_until(|| host.log.lock().unwrap().written.len() == 2);
    let log = host.log.lock().unwrap();
    assert_eq!(log.written, vec![9, 8]);
    assert_eq!(log.opened.len(), 1);
}

#[test]
fn playback_queue_memory_is_bounded_when_the_device_stalls() {
    let host = MockHost { write_delay: Duration::from_millis(300), ..Default::default() };
    let mut p = PulsePlayback::with_host(Arc::new(host), PlaybackOptions::default());
    let second = bytes(&vec![0i16; 8_000]); // 1 s of 8 kHz mono per wave
    for _ in 0..200 {
        p.wave(&pcm(1, 8_000), 0, Cow::Borrowed(&second));
    }
    assert!(p.playback_latency() <= Duration::from_secs(11), "queued {:?}", p.playback_latency());
    p.close();
}

/// Packet duration is the server's choice (up to 48 000 frames: 6 s at 8 kHz). Stopping must not
/// wait for a whole packet to be recorded.
#[test]
fn closing_the_microphone_does_not_wait_for_a_long_packet() {
    let host = RealTimeHost::default();
    let mut c = PulseCapture::with_host(Arc::new(host.clone()), CaptureOptions::default());
    let delivered = Arc::new(AtomicUsize::new(0));
    let d = delivered.clone();
    let rc = c.open(
        &pcm(1, 8_000),
        &pcm(1, 8_000),
        96_000,
        Box::new(move |_| {
            d.fetch_add(1, Ordering::Relaxed);
        }),
    );
    assert_eq!(rc, OpenReplyPdu::S_OK);
    // The device is read in short slices, not one 6 s read.
    let (_, fragment) = host.opened.lock().unwrap()[0];
    assert!(fragment <= 8_000 * 2 / 10, "fragment {fragment} is more than 100 ms of audio");
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    c.close();
    assert!(started.elapsed() < Duration::from_secs(1), "close took {:?}", started.elapsed());
    // Restarting (what a second Open or a format change does) is just as quick.
    assert_eq!(c.open(&pcm(1, 8_000), &pcm(1, 8_000), 96_000, Box::new(|_| {})), OpenReplyPdu::S_OK);
    let started = Instant::now();
    assert!(c.set_format(&pcm(2, 8_000), 96_000));
    drop(c);
    assert!(started.elapsed() < Duration::from_secs(1), "restart + drop took {:?}", started.elapsed());
    assert_eq!(delivered.load(Ordering::Relaxed), 0, "no partial packet may be delivered");
}

/// A sound server that stops delivering audio must not freeze the session thread, and a server
/// that keeps re-opening the microphone must not pile up stuck threads.
#[test]
fn stuck_microphone_never_blocks_close_and_cannot_pile_up_threads() {
    let host = RealTimeHost::default();
    host.stuck.store(true, Ordering::Relaxed);
    let mut c = PulseCapture::with_host(Arc::new(host.clone()), CaptureOptions::default());
    let delivered = Arc::new(AtomicUsize::new(0));
    let mut results = Vec::new();
    for _ in 0..8 {
        let d = delivered.clone();
        results.push(c.open(
            &pcm(1, 16_000),
            &pcm(1, 16_000),
            640,
            Box::new(move |_| {
                d.fetch_add(1, Ordering::Relaxed);
            }),
        ));
        let started = Instant::now();
        c.close();
        assert!(started.elapsed() < Duration::from_secs(2), "close blocked for {:?}", started.elapsed());
    }
    let opened = host.opened.lock().unwrap().len();
    assert!((1..=3).contains(&opened), "{opened} capture streams opened while the microphone was stuck");
    assert_eq!(results.iter().filter(|rc| **rc == OpenReplyPdu::S_OK).count(), opened);
    assert_eq!(*results.last().unwrap(), OpenReplyPdu::E_FAIL);

    // Once the device recovers, the abandoned threads exit without delivering stale audio and the
    // microphone can be opened again.
    host.stuck.store(false, Ordering::Relaxed);
    wait_until(|| {
        let rc = c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(|_| {}));
        c.close();
        rc == OpenReplyPdu::S_OK
    });
    assert_eq!(delivered.load(Ordering::Relaxed), 0, "a closed capture must not deliver packets");
}

/// The server can also close and reopen the whole microphone channel, which builds a new
/// capture each time: the session's thread limit must survive that.
#[test]
fn reopening_the_microphone_channel_cannot_reset_the_thread_limit() {
    let host = RealTimeHost::default();
    host.stuck.store(true, Ordering::Relaxed);
    let threads = MicThreads::default();
    let mut results = Vec::new();
    for _ in 0..8 {
        // One channel instance: Create, Open, Close.
        let mut c =
            PulseCapture::with_host_and_threads(Arc::new(host.clone()), CaptureOptions::default(), threads.clone());
        results.push(c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(|_| {})));
        let started = Instant::now();
        drop(c);
        assert!(started.elapsed() < Duration::from_secs(2), "closing blocked for {:?}", started.elapsed());
    }
    let opened = host.opened.lock().unwrap().len();
    assert!((1..=3).contains(&opened), "{opened} capture streams opened while the microphone was stuck");
    assert_eq!(*results.last().unwrap(), OpenReplyPdu::E_FAIL);

    host.stuck.store(false, Ordering::Relaxed);
    wait_until(|| {
        let mut c =
            PulseCapture::with_host_and_threads(Arc::new(host.clone()), CaptureOptions::default(), threads.clone());
        c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(|_| {})) == OpenReplyPdu::S_OK
    });
}

/// Counts info-and-above log events on the current thread.
struct CountLogs(Arc<AtomicUsize>);

impl tracing::Subscriber for CountLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() <= tracing::Level::INFO {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Every one of these handlers runs once per server PDU; none may log once per PDU.
#[test]
fn server_driven_log_lines_are_rate_limited() {
    let lines = Arc::new(AtomicUsize::new(0));
    tracing::subscriber::with_default(CountLogs(lines.clone()), || {
        let mut c = PulseCapture::with_host(Arc::new(MockHost::default()), CaptureOptions::default());
        let mut p = PulsePlayback::with_host(Arc::new(MockHost::default()), PlaybackOptions::default());
        let unplayable = [AudioFormat { format: WaveFormat::AAC_MS, ..pcm(2, 44_100) }];
        let evil = AudioFormat { n_channels: 256, ..pcm(2, 44_100) };
        for _ in 0..300 {
            c.choose_formats(&[pcm(2, 44_100)]);
            c.open(&evil, &pcm(2, 44_100), 1764, Box::new(|_| {}));
            c.set_format(&pcm(2, 44_100), 1764);
            p.choose_formats(&unplayable);
            p.choose_formats(&[pcm(2, 44_100)]);
            p.wave(&evil, 0, Cow::Owned(vec![0; 4]));
        }
        for i in 0..60 {
            // Open/close and alternating wave formats: each used to log two or three lines.
            assert_eq!(c.open(&pcm(1, 16_000), &pcm(1, 16_000), 640, Box::new(|_| {})), OpenReplyPdu::S_OK);
            c.close();
            p.wave(&pcm(if i % 2 == 0 { 1 } else { 2 }, 44_100), 0, Cow::Owned(vec![0; 4]));
        }
    });
    let lines = lines.load(Ordering::Relaxed);
    // 2 040 server PDUs above; each call site may log a burst of 5 per 30 s window.
    assert!(lines <= 120, "{lines} log lines for 2 040 server PDUs");
}
