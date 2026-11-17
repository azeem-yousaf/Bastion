//! Decoder tests against fixed H.264 fixtures (generated once with libx264, checked in).

use bastion_video::{Accel, DecoderOptions, FfmpegH264Decoder};
use ironrdp_egfx::decode::H264Decoder as _;

const RED: &[u8] = include_bytes!("fixtures/red_64x48.h264");
const TESTSRC: &[u8] = include_bytes!("fixtures/testsrc_320x240.h264");

/// Splits an Annex-B stream into access units: each unit ends after a slice NAL (type 1 or 5).
fn access_units(stream: &[u8]) -> Vec<Vec<u8>> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= stream.len() {
        if stream[i..i + 3] == [0, 0, 1] {
            let s = if i > 0 && stream[i - 1] == 0 { i - 1 } else { i };
            starts.push((s, stream[i + 3] & 0x1f));
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut units = Vec::new();
    let mut cur_start = 0;
    for (n, &(_, ty)) in starts.iter().enumerate() {
        if ty == 1 || ty == 5 {
            let end = starts.get(n + 1).map_or(stream.len(), |&(s, _)| s);
            units.push(stream[cur_start..end].to_vec());
            cur_start = end;
        }
    }
    units
}

/// Converts Annex-B to AVC (4-byte big-endian length prefixes).
fn to_avc(unit: &[u8]) -> Vec<u8> {
    let mut nals = Vec::new();
    let mut i = 0;
    let mut start = None;
    while i + 3 <= unit.len() {
        if unit[i..i + 3] == [0, 0, 1] {
            if let Some(s) = start {
                let mut e = i;
                if unit[e - 1] == 0 {
                    e -= 1;
                }
                nals.push(&unit[s..e]);
            }
            start = Some(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    if let Some(s) = start {
        nals.push(&unit[s..]);
    }
    let mut out = Vec::new();
    for n in nals {
        out.extend_from_slice(&(n.len() as u32).to_be_bytes());
        out.extend_from_slice(n);
    }
    out
}

fn software() -> FfmpegH264Decoder {
    let d = FfmpegH264Decoder::new(DecoderOptions { prefer_hardware: false, yuv420_planes: true }).unwrap();
    assert_eq!(d.accel(), Accel::Software);
    d
}

#[test]
fn splits_fixture_into_frames() {
    assert_eq!(access_units(RED).len(), 3);
    assert_eq!(access_units(TESTSRC).len(), 10);
}

#[test]
fn decodes_solid_red_with_correct_colour() {
    let mut d = software();
    for unit in access_units(RED) {
        let f = d.decode(&unit).expect("every access unit yields a picture (low delay)");
        assert_eq!((f.width(), f.height()), (64, 48));
        let px = &f.data()[(24 * 64 + 32) * 4..][..4];
        assert!(px[0] > 230 && px[1] < 30 && px[2] < 30, "expected red, got {px:?}");
        assert_eq!(px[3], 255);
    }
}

#[test]
fn yuv420_planes_have_expected_geometry() {
    let mut d = software();
    let unit = &access_units(TESTSRC)[0];
    let y = d.decode_yuv420(unit).unwrap();
    assert_eq!((y.width(), y.height()), (320, 240));
    assert_eq!(y.luma_row(239).unwrap().len(), 320);
    assert_eq!(y.u_row(119).unwrap().len(), 160);
    assert!(y.luma_row(240).is_none());
}

#[test]
fn accepts_avc_length_prefixed_input() {
    let mut d = software();
    for unit in access_units(TESTSRC) {
        let f = d.decode(&to_avc(&unit)).unwrap();
        assert_eq!((f.width(), f.height()), (320, 240));
    }
}

#[test]
fn garbage_input_errors_without_panicking() {
    let mut d = software();
    assert!(d.decode(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    assert!(d.decode(&[]).is_err());
    // Still usable afterwards, starting from an IDR.
    d.reset();
    assert!(d.decode(&access_units(RED)[0]).is_ok());
}

#[test]
fn every_frame_matches_between_software_and_hardware() {
    // Runs on machines with NVDEC/VAAPI; on others both paths are software and it still passes.
    let mut sw = software();
    let Ok(mut hw) = FfmpegH264Decoder::new(DecoderOptions { prefer_hardware: true, yuv420_planes: false }) else {
        return;
    };
    eprintln!("hardware path: {}", hw.accel().name());
    for unit in access_units(TESTSRC) {
        let a = sw.decode(&unit).unwrap();
        let b = hw.decode(&unit).unwrap();
        assert_eq!((a.width(), a.height()), (b.width(), b.height()));
        let max_diff = a.data().iter().zip(b.data()).map(|(x, y)| x.abs_diff(*y)).max().unwrap();
        assert!(max_diff <= 8, "hw/sw output differs by {max_diff}");
    }
}

/// The session switches between our SIMD conversion (`decode`) and IronRDP's spec conversion
/// (`decode_yuv420().to_rgba()`) depending on the stream, so both must give the same colours.
#[test]
fn fast_rgba_conversion_matches_ironrdp_spec_conversion() {
    let units = access_units(TESTSRC);
    let mut fast = software();
    let mut spec = software();
    let mut worst = 0u8;
    for unit in &units {
        let a = fast.decode(unit).unwrap();
        let b = spec.decode_yuv420(unit).unwrap().to_rgba();
        assert_eq!((a.width(), a.height()), (b.width(), b.height()));
        for (pa, pb) in a.data().as_chunks::<4>().0.iter().zip(b.data().as_chunks::<4>().0) {
            for c in 0..3 {
                worst = worst.max(pa[c].abs_diff(pb[c]));
            }
        }
    }
    assert!(worst <= 3, "colour mismatch up to {worst} levels");
}

#[test]
fn yuv420_switch_controls_supports_yuv420() {
    use ironrdp_egfx::decode::H264Decoder as _;
    let d = software();
    assert!(d.supports_yuv420());
    d.yuv420_switch().store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!d.supports_yuv420());
}
