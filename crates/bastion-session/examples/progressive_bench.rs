//! Benchmark of RemoteFX Progressive decoding (IronRDP's `ProgressiveDecoder`), the codec
//! Windows uses for most non-video desktop content.
//!
//! Encodes a desktop-like 3840×2160 image (gradients, text-like strokes, noisy photo areas)
//! into one progressive frame with IronRDP's own encoder, then times decoding it.
//!
//!   cargo run --release -p bastion-session --example progressive_bench

use std::time::Instant;

use ironrdp_graphics::progressive::{ProgressiveDecoder, encode_first_pass, rgba_to_ycbcr};
use ironrdp_pdu::codecs::rfx::RfxRectangle;
use ironrdp_pdu::codecs::rfx::progressive::{
    ComponentCodecQuant, ProgressiveBlock, ProgressiveCodecQuant, ProgressiveContextPdu, ProgressiveFrameBeginPdu,
    ProgressiveFrameEndPdu, ProgressiveRegion, ProgressiveSyncPdu, ProgressiveTile, TileFirst,
    encode_progressive_stream,
};

const W: u16 = 3840;
const H: u16 = 2160;
const TILE: u16 = 64;

/// Typical RemoteFX quantisation (coarser for higher-frequency bands).
const QUANT: ComponentCodecQuant =
    ComponentCodecQuant { ll3: 6, hl3: 6, lh3: 6, hh3: 6, hl2: 7, lh2: 7, hh2: 8, hl1: 8, lh1: 8, hh1: 9 };

fn pixel(x: u32, y: u32) -> [u8; 4] {
    let mut seed = x.wrapping_mul(73_856_093) ^ y.wrapping_mul(19_349_663);
    seed ^= seed >> 13;
    let noise = (seed.wrapping_mul(1_274_126_177) >> 24) as u8;
    match (x / 640 + y / 360) % 3 {
        // Window background with "text" strokes.
        0 if (y % 18 < 2 || (x / 7).is_multiple_of(3)) && (y % 18) < 12 => [20, 20, 20, 255],
        0 => [250, 250, 250, 255],
        // Smooth gradient.
        1 => [(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255],
        // Photo-like noisy area.
        _ => [noise, noise.wrapping_add(40), noise / 2, 255],
    }
}

fn encode_frame() -> Vec<u8> {
    let tiles_x = W.div_ceil(TILE);
    let tiles_y = H.div_ceil(TILE);
    let mut data: Vec<[Vec<u8>; 3]> = Vec::new();
    let mut idx = Vec::new();
    let mut rgba = vec![0u8; 64 * 64 * 4];
    let (mut y, mut cb, mut cr) = (vec![0i16; 4096], vec![0i16; 4096], vec![0i16; 4096]);
    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            for py in 0..64u32 {
                for px in 0..64u32 {
                    let p = pixel(u32::from(tx) * 64 + px, u32::from(ty) * 64 + py);
                    rgba[((py * 64 + px) * 4) as usize..][..4].copy_from_slice(&p);
                }
            }
            rgba_to_ycbcr(&rgba, &mut y, &mut cb, &mut cr);
            let enc = |c: &mut Vec<i16>| {
                let mut out = vec![0u8; 64 * 64 * 4];
                let n = encode_first_pass(c, &mut out, &QUANT, &ComponentCodecQuant::LOSSLESS, false).unwrap();
                out.truncate(n);
                out
            };
            data.push([enc(&mut y.clone()), enc(&mut cb.clone()), enc(&mut cr.clone())]);
            idx.push((tx, ty));
        }
    }
    let tiles = data
        .iter()
        .zip(&idx)
        .map(|(d, &(x_idx, y_idx))| {
            ProgressiveTile::First(TileFirst {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx,
                y_idx,
                flags: 0,
                quality: 0,
                y_data: &d[0],
                cb_data: &d[1],
                cr_data: &d[2],
                tail_data: &[],
            })
        })
        .collect();
    let blocks = vec![
        ProgressiveBlock::Sync(ProgressiveSyncPdu),
        ProgressiveBlock::Context(ProgressiveContextPdu { context_id: 0, tile_size: 0x40, flags: 0 }),
        ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: 1 }),
        ProgressiveBlock::Region(ProgressiveRegion {
            tile_size: 0x40,
            rects: vec![RfxRectangle { x: 0, y: 0, width: W, height: H }],
            quant_vals: vec![QUANT],
            quant_prog_vals: vec![ProgressiveCodecQuant {
                quality: 0,
                y_quant: ComponentCodecQuant::LOSSLESS,
                cb_quant: ComponentCodecQuant::LOSSLESS,
                cr_quant: ComponentCodecQuant::LOSSLESS,
            }],
            flags: 0,
            tiles,
        }),
        ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
    ];
    encode_progressive_stream(&blocks).unwrap()
}

fn main() {
    let stream = encode_frame();
    let tiles = usize::from(W.div_ceil(TILE)) * usize::from(H.div_ceil(TILE));
    println!("{W}x{H}: {tiles} tiles, {} KB encoded", stream.len() / 1024);
    let mut best = f64::MAX;
    let mut checksum = 0u64;
    for run in 0..6 {
        let mut dec = ProgressiveDecoder::new();
        let t = Instant::now();
        let out = dec.decode_bitmap(1, 0, W, H, &stream).unwrap();
        let ms = t.elapsed().as_secs_f64() * 1e3;
        checksum = out.iter().map(|t| t.pixels.iter().map(|&b| u64::from(b)).sum::<u64>()).sum();
        if run > 0 {
            best = best.min(ms);
        }
        assert_eq!(out.len(), tiles);
    }
    println!("full-frame decode: {best:.1} ms ({:.1} µs/tile)  checksum {checksum}", best * 1e3 / tiles as f64);
}
