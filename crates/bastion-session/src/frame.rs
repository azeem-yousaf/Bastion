//! Shared framebuffer between the session thread (writer) and the renderer (reader).
//!
//! Only dirty rectangles are copied out of the decoder's image, and the renderer only
//! uploads the accumulated dirty region to the GPU — so idle desktops cost ~nothing.

use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
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
    pub dirty: Option<Rect>,
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
}

impl SharedFrame {
    pub fn lock(&self) -> std::sync::MutexGuard<'_, FrameState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Copies `rect` from `src` (tightly packed RGBA, `src_width` wide) into the shared frame.
    pub fn update_from(&self, src: &[u8], src_width: u32, src_height: u32, rect: Rect) {
        let mut st = self.lock();
        if st.width != src_width || st.height != src_height {
            st.width = src_width;
            st.height = src_height;
            st.data = src.to_vec();
            st.generation += 1;
            st.dirty = Some(Rect { x: 0, y: 0, w: src_width, h: src_height });
            st.dirty_since.get_or_insert_with(std::time::Instant::now);
            return;
        }
        let rect = clamp(rect, src_width, src_height);
        if rect.w == 0 || rect.h == 0 {
            return;
        }
        let stride = src_width as usize * 4;
        let row_bytes = rect.w as usize * 4;
        for row in rect.y..rect.y + rect.h {
            let off = row as usize * stride + rect.x as usize * 4;
            st.data[off..off + row_bytes].copy_from_slice(&src[off..off + row_bytes]);
        }
        st.dirty = Some(match st.dirty {
            Some(d) => d.union(rect),
            None => rect,
        });
        st.dirty_since.get_or_insert_with(std::time::Instant::now);
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
        f.lock().dirty = None;
        f.update_from(&src, 10, 10, Rect { x: 2, y: 2, w: 2, h: 2 });
        f.update_from(&src, 10, 10, Rect { x: 8, y: 8, w: 5, h: 5 });
        assert_eq!(f.lock().dirty, Some(Rect { x: 2, y: 2, w: 8, h: 8 }));
    }
}
