//! Shared framebuffer between the session thread (writer) and the renderer (reader).
//!
//! Only dirty rectangles are copied out of the decoder's image, and the renderer only
//! uploads those rectangles to the GPU — so idle desktops cost ~nothing. Rectangles are kept
//! as a short list rather than one bounding box: on a 6400×2160 multi-monitor desktop a small
//! change on each screen would otherwise copy and upload nearly the whole 55 MB frame.

use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// More dirty rectangles than this are collapsed into their bounding box (per-rectangle upload
/// overhead would outweigh the saved bytes).
pub const MAX_DIRTY_RECTS: usize = 32;

/// Limits on the frame size the remote computer chooses (shared with the video decoder): up
/// to RDP's virtual-desktop side per side, so wide multi-monitor layouts fit, and at most
/// 8192 × 8192 pixels in area. A server announcing more is refused rather than given a
/// multi-gigabyte buffer.
pub use bastion_video::{MAX_DESKTOP_PIXELS, MAX_DESKTOP_SIDE, desktop_size_ok};

/// Regions written per lock in [`SharedFrame::apply_regions`]. The renderer (the one UI thread
/// for every window) takes the same lock, so a server that produces millions of tiny regions
/// must not be able to hold it for all of them. Far above what a real frame produces (a full
/// RemoteFX Progressive update of the largest desktop area, 8192×8192 pixels, is 16,384 tiles),
/// so real frames still land atomically.
const REGIONS_PER_LOCK: usize = 32_768;

/// Bytes of a `width`×`height` RGBA frame; `None` if it is larger than Bastion accepts.
fn frame_len(width: u32, height: u32) -> Option<usize> {
    if width != 0 && height != 0 && !desktop_size_ok(width, height) {
        return None;
    }
    (width as usize).checked_mul(height as usize)?.checked_mul(4)
}

impl Rect {
    pub fn area(self) -> u64 {
        u64::from(self.w) * u64::from(self.h)
    }

    pub fn union(self, o: Rect) -> Rect {
        let x0 = self.x.min(o.x);
        let y0 = self.y.min(o.y);
        let x1 = (self.x + self.w).max(o.x + o.w);
        let y1 = (self.y + self.h).max(o.y + o.h);
        Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
    }
}

/// RGBA8 framebuffer with a pending dirty region.
#[derive(Debug, Default)]
pub struct FrameState {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
    /// Regions changed since the renderer last uploaded (see [`MAX_DIRTY_RECTS`]).
    pub dirty: Vec<Rect>,
    /// Bumped whenever the size changes (renderer must recreate its texture).
    pub generation: u64,
    /// When the pending dirty region first became dirty (for frame-latency metrics).
    pub dirty_since: Option<std::time::Instant>,
}

#[derive(Debug, Default)]
pub struct SharedFrame {
    inner: Mutex<FrameState>,
    /// Set by the session when new pixels arrived; cleared by the renderer when it presents.
    /// Used to coalesce wake-ups (at most one pending redraw request at a time).
    pub needs_present: std::sync::atomic::AtomicBool,
    /// Screen updates written so far (for the frame rate shown by the quality indicator).
    pub updates: std::sync::atomic::AtomicU64,
    /// The session's graphics pipeline threads (see `gfx::Pipelines`): kept here because this
    /// is the one object every graphics channel of a session shares.
    pub(crate) gfx: Mutex<crate::gfx::Pipelines>,
    /// Tests: refuse every size, as for one beyond the limits. The graphics pipeline allows no
    /// more than [`desktop_size_ok`] does, so its refusal path cannot be reached otherwise.
    #[cfg(test)]
    pub(crate) refuse_resets: std::sync::atomic::AtomicBool,
}

/// Adds `r` to the dirty list, merging it with rectangles it overlaps or abuts when the merge
/// covers no extra pixels beyond the two (so merging never inflates the upload much).
fn add_dirty(list: &mut Vec<Rect>, mut r: Rect) {
    while let Some(i) = list.iter().position(|d| d.union(r).area() <= d.area() + r.area()) {
        r = list.swap_remove(i).union(r);
    }
    list.push(r);
    if list.len() > MAX_DIRTY_RECTS {
        let all = list.iter().copied().reduce(Rect::union).expect("non-empty");
        list.clear();
        list.push(all);
    }
}

impl SharedFrame {
    pub fn lock(&self) -> std::sync::MutexGuard<'_, FrameState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Sets the frame size announced by the graphics pipeline. A new size clears the frame (the
    /// server repaints after a reset); the same size keeps the pixels.
    ///
    /// Returns `false`, leaving the frame untouched, for a size beyond [`desktop_size_ok`]: the
    /// size comes from the server, and nothing is allocated for one no display could have.
    pub fn reset(&self, width: u32, height: u32) -> bool {
        #[cfg(test)]
        if self.refuse_resets.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let Some(len) = frame_len(width, height) else {
            return false;
        };
        let mut st = self.lock();
        if st.width != width || st.height != height {
            st.width = width;
            st.height = height;
            st.data = vec![0; len];
            st.generation += 1;
        }
        st.dirty = vec![Rect { x: 0, y: 0, w: width, h: height }];
        st.dirty_since.get_or_insert_with(std::time::Instant::now);
        true
    }

    /// Writes regions of tightly packed RGBA rows (as the graphics pipeline produces them)
    /// into the frame. Regions outside the frame are clipped. Returns the pixels written.
    pub fn apply_regions<'a>(&self, regions: impl IntoIterator<Item = (Rect, &'a [u8])>) -> u64 {
        self.apply_regions_chunked(regions, REGIONS_PER_LOCK)
    }

    /// [`Self::apply_regions`], releasing the lock after every `per_lock` regions so the
    /// renderer is never kept waiting for an unbounded list (see [`REGIONS_PER_LOCK`]).
    fn apply_regions_chunked<'a>(&self, regions: impl IntoIterator<Item = (Rect, &'a [u8])>, per_lock: usize) -> u64 {
        let mut regions = regions.into_iter();
        let mut copied = 0;
        loop {
            let mut st = self.lock();
            let (fw, fh) = (st.width, st.height);
            let stride = fw as usize * 4;
            let mut taken = 0;
            for (rect, src) in regions.by_ref().take(per_lock) {
                taken += 1;
                let clip = clamp(rect, fw, fh);
                if clip.w == 0 || clip.h == 0 || (src.len() as u64) < rect.area().saturating_mul(4) {
                    continue;
                }
                let src_stride = rect.w as usize * 4;
                let row_bytes = clip.w as usize * 4;
                for row in 0..clip.h as usize {
                    let s = row * src_stride;
                    let d = (clip.y as usize + row) * stride + clip.x as usize * 4;
                    st.data[d..d + row_bytes].copy_from_slice(&src[s..s + row_bytes]);
                }
                add_dirty(&mut st.dirty, clip);
                copied += clip.area();
            }
            if taken < per_lock {
                if copied > 0 {
                    st.dirty_since.get_or_insert_with(std::time::Instant::now);
                    self.updates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return copied;
            }
            if copied > 0 {
                st.dirty_since.get_or_insert_with(std::time::Instant::now);
            }
        }
    }

    /// Copies `rect` from `src` (tightly packed RGBA, `src_width` wide) into the shared frame.
    pub fn update_from(&self, src: &[u8], src_width: u32, src_height: u32, rect: Rect) -> u64 {
        self.update_rects(src, src_width, src_height, &[rect])
    }

    /// Copies each of `rects` from `src` under one lock. Returns the number of pixels copied.
    ///
    /// A source larger than [`desktop_size_ok`] allows, or shorter than its stated size, is ignored
    /// (nothing is copied or allocated).
    pub fn update_rects(&self, src: &[u8], src_width: u32, src_height: u32, rects: &[Rect]) -> u64 {
        let Some(len) = frame_len(src_width, src_height).filter(|&len| src.len() >= len) else {
            return 0;
        };
        let mut st = self.lock();
        if st.width != src_width || st.height != src_height {
            st.width = src_width;
            st.height = src_height;
            st.data = src[..len].to_vec();
            st.generation += 1;
            st.dirty = vec![Rect { x: 0, y: 0, w: src_width, h: src_height }];
            st.dirty_since.get_or_insert_with(std::time::Instant::now);
            self.updates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return u64::from(src_width) * u64::from(src_height);
        }
        let stride = src_width as usize * 4;
        let mut copied = 0;
        for &rect in rects {
            let rect = clamp(rect, src_width, src_height);
            if rect.w == 0 || rect.h == 0 {
                continue;
            }
            let row_bytes = rect.w as usize * 4;
            for row in rect.y..rect.y + rect.h {
                let off = row as usize * stride + rect.x as usize * 4;
                st.data[off..off + row_bytes].copy_from_slice(&src[off..off + row_bytes]);
            }
            add_dirty(&mut st.dirty, rect);
            copied += rect.area();
        }
        if copied > 0 {
            st.dirty_since.get_or_insert_with(std::time::Instant::now);
            self.updates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        copied
    }
}

fn clamp(r: Rect, w: u32, h: u32) -> Rect {
    let x = r.x.min(w);
    let y = r.y.min(h);
    Rect { x, y, w: r.w.min(w - x), h: r.h.min(h - y) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_accumulates() {
        let f = SharedFrame::default();
        let src = vec![7u8; 10 * 10 * 4];
        f.update_from(&src, 10, 10, Rect { x: 0, y: 0, w: 1, h: 1 });
        assert_eq!(f.lock().generation, 1);
        f.lock().dirty.clear();
        f.update_from(&src, 10, 10, Rect { x: 2, y: 2, w: 2, h: 2 });
        f.update_from(&src, 10, 10, Rect { x: 8, y: 8, w: 5, h: 5 });
        // Far apart: kept separate (clamped to the frame), not one 8×8 bounding box.
        assert_eq!(f.lock().dirty, vec![Rect { x: 2, y: 2, w: 2, h: 2 }, Rect { x: 8, y: 8, w: 2, h: 2 }]);
    }

    #[test]
    fn regions_are_written_row_by_row_and_clipped() {
        let f = SharedFrame::default();
        f.reset(8, 4);
        assert_eq!(f.lock().generation, 1);
        f.lock().dirty.clear();
        // A 3×2 region of distinct pixels at (6, 3): only the 2×1 part inside the frame lands.
        let src: Vec<u8> = (0..3 * 2 * 4).map(|i| i as u8).collect();
        let n = f.apply_regions([(Rect { x: 6, y: 3, w: 3, h: 2 }, &src[..])]);
        assert_eq!(n, 2);
        let st = f.lock();
        assert_eq!(&st.data[(3 * 8 + 6) * 4..(3 * 8 + 8) * 4], &src[..8]);
        assert_eq!(st.dirty, vec![Rect { x: 6, y: 3, w: 2, h: 1 }]);
        drop(st);
        // Same size again keeps the pixels and the texture generation.
        f.reset(8, 4);
        assert_eq!(f.lock().generation, 1);
        assert_eq!(f.lock().data[(3 * 8 + 6) * 4], 0);
    }

    #[test]
    fn wide_multi_monitor_desktops_are_accepted() {
        // ResetGraphics for three 4K monitors side by side, 4K + 4K + 2560, and three stacked.
        for (w, h) in [(11_520, 2160), (10_240, 2160), (3840, 6480)] {
            let f = SharedFrame::default();
            assert!(f.reset(w, h), "{w}x{h}");
            assert_eq!(f.lock().data.len(), w as usize * h as usize * 4);
            let src = vec![0u8; w as usize * h as usize * 4];
            let f = SharedFrame::default();
            assert_eq!(f.update_from(&src, w, h, Rect { x: 0, y: 0, w: 1, h: 1 }), u64::from(w) * u64::from(h));
        }
    }

    #[test]
    fn sizes_no_display_could_have_are_refused_without_allocating() {
        let f = SharedFrame::default();
        assert!(f.reset(64, 48));
        f.lock().dirty.clear();
        // What a hostile ResetGraphics can ask for: one edge over the limit, an area over it, or
        // both (17 GB).
        for (w, h) in
            [(MAX_DESKTOP_SIDE + 1, 8), (8, MAX_DESKTOP_SIDE + 1), (8192, 8193), (32_766, 32_766), (u32::MAX, u32::MAX)]
        {
            assert!(!f.reset(w, h), "{w}x{h}");
        }
        let st = f.lock();
        assert_eq!((st.width, st.height, st.data.len(), st.generation), (64, 48, 64 * 48 * 4, 1));
        assert!(st.dirty.is_empty(), "a refused reset leaves the frame alone");
        drop(st);
        assert!(f.reset(8192, 8192), "the largest area still works");

        // The legacy path sizes the frame from the source image.
        let f = SharedFrame::default();
        let wide = vec![0u8; (MAX_DESKTOP_SIDE as usize + 1) * 4];
        assert_eq!(f.update_from(&wide, MAX_DESKTOP_SIDE + 1, 1, Rect { x: 0, y: 0, w: 1, h: 1 }), 0);
        assert_eq!(f.update_from(&wide, 65_535, 65_535, Rect { x: 0, y: 0, w: 1, h: 1 }), 0);
        // A source shorter than it claims must not be read past its end.
        assert_eq!(f.update_from(&wide[..16], 4, 4, Rect { x: 0, y: 0, w: 4, h: 4 }), 0);
        let st = f.lock();
        assert_eq!((st.width, st.height, st.generation), (0, 0, 0));
        assert!(st.data.is_empty());
    }

    #[test]
    fn many_regions_are_applied_in_bounded_lock_holds_with_the_same_result() {
        use std::sync::atomic::Ordering::Relaxed;
        let regions: Vec<(Rect, [u8; 4])> =
            (0..100u32).map(|i| (Rect { x: (i * 7) % 16, y: (i * 3) % 8, w: 1, h: 1 }, [i as u8, 1, 2, 3])).collect();
        let apply = |per_lock: usize| {
            let f = SharedFrame::default();
            f.reset(16, 8);
            f.lock().dirty.clear();
            let n = f.apply_regions_chunked(regions.iter().map(|(r, px)| (*r, &px[..])), per_lock);
            let st = f.lock();
            (n, st.data.clone(), st.dirty.clone(), f.updates.load(Relaxed))
        };
        let whole = apply(usize::MAX);
        assert_eq!(whole.0, 100);
        assert_eq!(whole.3, 1);
        // 7 per lock: the lock is released 14 times on the way; pixels, dirty list and the
        // update count are what one pass gives. Exactly divisible chunk sizes end cleanly too.
        assert_eq!(apply(7), whole);
        assert_eq!(apply(10), whole);
        assert_eq!(apply(100), whole);
    }

    #[test]
    fn updates_are_counted_only_when_pixels_change() {
        use std::sync::atomic::Ordering::Relaxed;
        let f = SharedFrame::default();
        let src = vec![1u8; 4 * 4 * 4];
        f.update_from(&src, 4, 4, Rect { x: 0, y: 0, w: 1, h: 1 }); // first frame (resize)
        f.update_from(&src, 4, 4, Rect { x: 1, y: 1, w: 1, h: 1 });
        f.update_from(&src, 4, 4, Rect { x: 9, y: 9, w: 1, h: 1 }); // entirely outside
        assert_eq!(f.updates.load(Relaxed), 2);
        f.apply_regions([(Rect { x: 0, y: 0, w: 1, h: 1 }, &src[..4])]);
        f.apply_regions(std::iter::empty());
        assert_eq!(f.updates.load(Relaxed), 3);
    }

    #[test]
    fn overlapping_and_adjacent_rects_merge() {
        let mut d = Vec::new();
        add_dirty(&mut d, Rect { x: 0, y: 0, w: 10, h: 10 });
        add_dirty(&mut d, Rect { x: 10, y: 0, w: 10, h: 10 }); // abuts: merges, no waste
        add_dirty(&mut d, Rect { x: 5, y: 5, w: 2, h: 2 }); // inside: absorbed
        assert_eq!(d, vec![Rect { x: 0, y: 0, w: 20, h: 10 }]);
    }

    #[test]
    fn small_changes_on_two_monitors_stay_small() {
        // A clock on each screen of a 6400×2160 desktop: ~0.03 % of the pixels, not ~100 %.
        let mut d = Vec::new();
        add_dirty(&mut d, Rect { x: 2400, y: 1400, w: 100, h: 30 });
        add_dirty(&mut d, Rect { x: 6200, y: 2120, w: 100, h: 30 });
        assert_eq!(d.iter().map(|r| r.area()).sum::<u64>(), 6000);
    }

    #[test]
    fn too_many_rects_collapse_to_their_bounds() {
        let mut d = Vec::new();
        for i in 0..=MAX_DIRTY_RECTS as u32 {
            add_dirty(&mut d, Rect { x: i * 10, y: (i % 2) * 50, w: 2, h: 2 });
        }
        assert_eq!(d.len(), 1);
    }
}
