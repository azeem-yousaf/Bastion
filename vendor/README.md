# Patched upstream crates

Crates here replace their crates.io versions through `[patch.crates-io]` in the workspace
`Cargo.toml`. Each is the published release plus a small patch, recorded in
`<crate>.patch` (a diff against the pristine crate) so it can be re-applied on upgrade or
proposed upstream.

## ironrdp-graphics 0.11.0 — parallel RemoteFX Progressive decoding

RemoteFX Progressive is the codec Windows uses for most non-video desktop content. IronRDP
decoded each REGION's 64×64 tiles one at a time on one core, and stored every tile's
reference coefficients (24 KB) inline in a `BTreeMap`, where inserts move whole values
around inside tree nodes. A 3840×2160 frame took 252 ms on an i9-10940X.

The patch:
- splits `decode_tile_block` into the per-tile decode (`decode_one_tile`) and its
  bookkeeping, unchanged in behaviour;
- adds `decode_region_tiles`: with ≥ 8 tiles and no tile repeated, tile states are taken out
  of the grid, decoded in parallel with rayon, and put back; references are updated afterwards
  in block order, so results are identical to sequential decoding;
- stores reference coefficients boxed (`BTreeMap<_, Box<DecDwtQ>>`), boxed by the workers.

Result: 252 ms → 27 ms for the full frame, bit-identical output
(`cargo run --release -p bastion-session --example progressive_bench`). IronRDP's own test
suite passes, plus `parallel_region_decode_matches_sequential` (run by `ci.sh`).

### ZGFX decompression

Every graphics-channel message is ZGFX (RDP 8 bulk) compressed. IronRDP decoded tokens by
comparing bit prefixes against its token table one `bitvec` slice at a time and wrote history
byte by byte: ~12 MB/s, which made up most of ClearCodec's per-message cost on a real session.
The patch adds a table-driven decoder (`zgfx::fast`: 9-bit lookup table built from
`TOKEN_TABLE`, 64-bit bit reader, matches copied from the output or history, history appended
once per segment). The original stays as the test reference.

Result on a recorded session (1,855 messages, 51 MB out): 2,084 ms → 163 ms, identical output
(`fast_decoder_matches_reference_on_compressed_streams`; with a recording,
`BASTION_ZGFX_CAPTURE=… cargo test --release --manifest-path vendor/ironrdp-graphics/Cargo.toml
--lib fast_decoder_matches_reference_on_capture -- --ignored`).

## ironrdp-egfx 0.5.0 — AVC420 without the intermediate copy

Each AVC420 region was copied out of the decoded frame into a `Vec` (for the handler's
`BitmapUpdate::data`) and then blitted into the surface. The patch adds
`GraphicsPipelineHandler::wants_bitmap_data` (default `true`, unchanged behaviour); when a
handler returns `false` (Bastion's does), regions are blitted straight from the frame
(`Compositor::apply_bitmap_from`). ~1.6 ms per 2560×1440 frame. Surfaces are byte-identical
either way (`avc420_direct_blit_matches_copy_path`).

## Verifying the whole pipeline

`examples/gfx_replay.rs` replays a recording (`BASTION_GFX_CAPTURE`) and prints a checksum of
every region updated over the session. With `BASTION_NO_HWDEC=1` (deterministic software
decoding) it matched the unpatched pipeline exactly on a real session.

## Upgrading

Copy the new release here, re-apply `<crate>.patch`, regenerate it against the pristine crate,
and run `./ci.sh`, the benchmarks and a recorded replay (compare checksums with the previous
build).
