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

To upgrade: copy the new release here, re-apply `ironrdp-graphics.patch`, regenerate it, and
run `./ci.sh` and the benchmark.
