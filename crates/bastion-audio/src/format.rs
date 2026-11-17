//! Audio format helpers shared by playback and capture.

use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};

use crate::host::PcmSpec;

/// Most channels any server-chosen format may have (7.1 surround).
pub const MAX_CHANNELS: u16 = 8;
/// Lowest sample rate any server-chosen format may have.
pub const MIN_SAMPLE_RATE: u32 = 4_000;
/// Highest sample rate any server-chosen format may have.
pub const MAX_SAMPLE_RATE: u32 = 192_000;

/// KSDATAFORMAT_SUBTYPE_PCM {00000001-0000-0010-8000-00AA00389B71} as stored in WAVEFORMATEXTENSIBLE.
const SUBTYPE_PCM: [u8; 16] = [0x01, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xAA, 0, 0x38, 0x9B, 0x71];

/// Windows 10/11 describe plain PCM as WAVE_FORMAT_EXTENSIBLE (0xFFFE) with a PCM sub-format.
/// Returns the equivalent plain-PCM format, or the input unchanged.
pub fn normalize(f: &AudioFormat) -> AudioFormat {
    if f.format == WaveFormat::EXTENSIBLE
        && let Some(d) = &f.data
    {
        // cbSize payload: wValidBitsPerSample(2) + dwChannelMask(4) + SubFormat GUID(16)
        if d.len() >= 22 && d[6..22] == SUBTYPE_PCM {
            return AudioFormat { format: WaveFormat::PCM, data: None, ..f.clone() };
        }
    }
    f.clone()
}

pub fn is_pcm16(f: &AudioFormat) -> bool {
    let n = normalize(f);
    n.format == WaveFormat::PCM && n.bits_per_sample == 16
}

/// The PCM shape (rate, channels) of a server-chosen format, or `None` when its parameters are
/// outside what any real server sends.
///
/// Every WAVEFORMATEX that reaches a device or a size calculation goes through this: the fields
/// are attacker-controlled, and a zero or huge channel count or sample rate would otherwise turn
/// into divisions by zero, truncated channel counts or absurd buffer sizes.
pub fn pcm_spec(f: &AudioFormat) -> Option<PcmSpec> {
    let n = normalize(f);
    if !(1..=MAX_CHANNELS).contains(&n.n_channels)
        || !(MIN_SAMPLE_RATE..=MAX_SAMPLE_RATE).contains(&n.n_samples_per_sec)
        || n.n_block_align == 0
    {
        return None;
    }
    if n.format == WaveFormat::PCM {
        // Only the sample widths the codec handles, with a block alignment that matches them.
        let bytes_per_sample = match n.bits_per_sample {
            8 => 1,
            16 => 2,
            _ => return None,
        };
        if n.n_block_align != n.n_channels * bytes_per_sample {
            return None;
        }
    }
    Some(PcmSpec { rate: n.n_samples_per_sec, channels: u8::try_from(n.n_channels).ok()? })
}

#[cfg(test)]
pub(crate) fn extensible_pcm(channels: u16, rate: u32) -> AudioFormat {
    let mut data = vec![16, 0, 3, 0, 0, 0];
    data.extend_from_slice(&SUBTYPE_PCM);
    AudioFormat {
        format: WaveFormat::EXTENSIBLE,
        n_channels: channels,
        n_samples_per_sec: rate,
        n_avg_bytes_per_sec: rate * u32::from(channels) * 2,
        n_block_align: channels * 2,
        bits_per_sample: 16,
        data: Some(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensible_pcm_from_real_windows_server_is_pcm() {
        // Exact bytes logged from the user's Windows PC.
        let f = AudioFormat {
            format: WaveFormat::EXTENSIBLE,
            n_channels: 2,
            n_samples_per_sec: 44100,
            n_avg_bytes_per_sec: 176400,
            n_block_align: 4,
            bits_per_sample: 16,
            data: Some(vec![16, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113]),
        };
        assert!(is_pcm16(&f));
        assert_eq!(normalize(&f).format, WaveFormat::PCM);
        assert_eq!(normalize(&f).n_samples_per_sec, 44100);
    }

    #[test]
    fn extensible_float_is_not_pcm() {
        let mut f = extensible_pcm(2, 48000);
        f.data.as_mut().unwrap()[6] = 3; // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
        assert!(!is_pcm16(&f));
    }

    fn pcm(channels: u16, rate: u32, bits: u16) -> AudioFormat {
        AudioFormat {
            format: WaveFormat::PCM,
            n_channels: channels,
            n_samples_per_sec: rate,
            n_avg_bytes_per_sec: rate.wrapping_mul(u32::from(channels)).wrapping_mul(u32::from(bits / 8)),
            n_block_align: channels.wrapping_mul(bits / 8),
            bits_per_sample: bits,
            data: None,
        }
    }

    #[test]
    fn sane_formats_have_a_pcm_spec() {
        assert_eq!(pcm_spec(&pcm(2, 44_100, 16)), Some(PcmSpec { rate: 44_100, channels: 2 }));
        assert_eq!(pcm_spec(&pcm(1, 8_000, 8)), Some(PcmSpec { rate: 8_000, channels: 1 }));
        assert_eq!(pcm_spec(&pcm(8, 192_000, 16)), Some(PcmSpec { rate: 192_000, channels: 8 }));
        assert_eq!(pcm_spec(&extensible_pcm(2, 48_000)), Some(PcmSpec { rate: 48_000, channels: 2 }));
    }

    #[test]
    fn hostile_formats_have_no_pcm_spec() {
        // Channel counts that are zero, too many, or that truncate to something else in a u8.
        for channels in [0, 9, 255, 256, 257, 0xFF00, u16::MAX] {
            assert_eq!(pcm_spec(&pcm(channels, 48_000, 16)), None, "{channels} channels");
        }
        for rate in [0, 1, 3_999, 192_001, u32::MAX] {
            assert_eq!(pcm_spec(&pcm(2, rate, 16)), None, "{rate} Hz");
        }
        for bits in [0, 4, 24, 32] {
            assert_eq!(pcm_spec(&pcm(2, 48_000, bits)), None, "{bits} bit");
        }
        // Block alignment must be non-zero and match the sample layout.
        assert_eq!(pcm_spec(&AudioFormat { n_block_align: 0, ..pcm(2, 48_000, 16) }), None);
        assert_eq!(pcm_spec(&AudioFormat { n_block_align: 3, ..pcm(2, 48_000, 16) }), None);
        assert_eq!(pcm_spec(&AudioFormat { n_block_align: 0, format: WaveFormat::ALAW, ..pcm(1, 8_000, 8) }), None);
    }
}
