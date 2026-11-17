//! Audio format helpers shared by playback and capture.

use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};

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
}
