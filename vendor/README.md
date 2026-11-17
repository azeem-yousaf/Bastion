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

### Progressive tile budget (hardening)

A tile's state is ~37 KB and its reference 24 KB, created by a tile block that can be 26 bytes
on the wire, and nothing bounded how many a server could create. The patch:
- caps tile states and, separately, references at `MAX_LIVE_TILES` (32,768: twice what an
  8192×8192 desktop needs) across all surfaces; past it tiles fail with
  `ProgressiveDecodeError::TileBudgetExceeded` (the parallel path refuses the region before
  touching the grid);
- returns a surface's tiles to the budget when it is deleted or resized;
- no longer allocates state for an upgrade block whose tile never had a first pass (it was
  created only to be skipped);
- once three quarters of the budget is in use, drops the least recently decoded surfaces
  (never the one being decoded), keeping their band layout. That reclaims surfaces abandoned
  without `delete_surface` — the EGFX client keeps Progressive state across `ResetGraphics`.

Pixels for streams within the budget are unchanged. Tests:
`live_tiles_are_capped_and_released_with_their_surface`,
`references_are_capped_separately_from_tile_state`,
`upgrades_for_tiles_without_a_first_pass_allocate_nothing`,
`abandoned_surfaces_are_evicted_before_they_exhaust_the_tile_budget`.

## ironrdp-egfx 0.5.0 — AVC420 without the intermediate copy

Each AVC420 region was copied out of the decoded frame into a `Vec` (for the handler's
`BitmapUpdate::data`) and then blitted into the surface. The patch adds
`GraphicsPipelineHandler::wants_bitmap_data` (default `true`, unchanged behaviour); when a
handler returns `false` (Bastion's does), regions are blitted straight from the frame
(`Compositor::apply_bitmap_from`). ~1.6 ms per 2560×1440 frame. Surfaces are byte-identical
either way (`avc420_direct_blit_matches_copy_path`).

### Hardening against hostile servers

Everything below only changes what happens to input no real server sends. The egfx patch does
not depend on the patched ironrdp-graphics (its tests build against the crates.io one).

- **Progressive only for surfaces with a canvas.** The client tracks every `CreateSurface`,
  including ones the compositor refuses (over 16384 px or over its 256 MiB budget), and used
  to run the Progressive decoder for them with a tile grid of up to 512×512. Such updates are
  now dropped before decoding
  (`progressive_updates_for_a_surface_without_a_canvas_never_reach_the_decoder`).
- **Per-message pixel-work allowance** (`MAX_MESSAGE_PIXEL_WORK`, 2^30 pixels). `SolidFill`
  rectangles, `SurfaceToSurface`/`CacheToSurface` points, `SurfaceToCache` copies and AVC420
  region rectangles cost a few bytes each and up to a whole surface of writes; one small
  message could occupy the graphics thread for hours. Past the allowance they are skipped
  until the next message (`repeated_fills_and_copies_stop_at_the_message_work_allowance`).
- **Queued updates are charged for their overhead** (`UPDATE_OVERHEAD`), so millions of 1×1
  updates cannot hold many times the compositor budget on the heap
  (`tiny_updates_are_charged_for_their_overhead`).
- **PDUs are dispatched as they are decoded** instead of first being collected into a
  `Vec<GfxPdu>` (gigabytes for a 256 MiB message of ten-byte PDUs). Order is unchanged; on a
  malformed message the PDUs before the bad one are now applied rather than none.
- **Per-PDU warnings are throttled** (`warn_throttled!` in `lib.rs`: the 1st, 2nd, 4th, 8th…
  occurrence per call site, with the count): the header flags check, the "unknown surface"
  and rectangle warnings, capability-confirm parse failures, AVC NAL length errors and the
  AVC420 empty-region warning (`a_call_site_logs_logarithmically_often`).

## Verifying the whole pipeline

`examples/gfx_replay.rs` replays a recording (`BASTION_GFX_CAPTURE`) and prints a checksum of
every region updated over the session. With `BASTION_NO_HWDEC=1` (deterministic software
decoding) it matched the unpatched pipeline exactly on a real session.

## Upgrading

Copy the new release here, re-apply `<crate>.patch`, regenerate it against the pristine crate,
and run `./ci.sh`, the benchmarks and a recorded replay (compare checksums with the previous
build).
