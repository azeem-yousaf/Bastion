//! Wiping freed memory while a password is being typed.
//!
//! egui's `TextEdit` copies the text it edits (masked or not) on every frame: `prev_text`, undo
//! snapshots, and the `Event::Text`/`Event::Paste`/IME strings that delivered each keystroke.
//! Those copies are freed without being cleared, so the password would linger on the heap. While
//! a [`WipeScope`] is alive, [`WipingAllocator`] (the app's global allocator) zeroes every small
//! allocation (at most [`WIPE_MAX`] bytes) before it is freed, and moves small reallocations itself
//! so the old block is zeroed too. Larger blocks — frame and PDU buffers of running sessions, which
//! never hold what is typed into the prompt — keep the system allocator's fast paths. Outside a
//! scope it is the system allocator plus one relaxed atomic load per free.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static SCOPES: AtomicUsize = AtomicUsize::new(0);

/// Largest block wiped in a scope. Passwords are short, and so are egui's copies of them (the
/// field's text, its previous text, the key events that typed it).
pub const WIPE_MAX: usize = 4096;

/// While any of these is alive, freed memory is zeroed (see the module docs).
#[derive(Debug)]
#[must_use = "freed memory is only wiped while the scope is alive"]
pub struct WipeScope(());

impl WipeScope {
    pub fn begin() -> Self {
        SCOPES.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for WipeScope {
    fn drop(&mut self) {
        SCOPES.fetch_sub(1, Ordering::SeqCst);
    }
}

/// True while a [`WipeScope`] is alive.
pub fn active() -> bool {
    SCOPES.load(Ordering::Relaxed) != 0
}

/// Zeroes `len` bytes at `ptr` in a way the optimiser can't drop as a dead store before `free`.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    // SAFETY: guaranteed by the caller.
    unsafe { std::ptr::write_bytes(ptr, 0, len) };
    // Makes the zeroed block observable, so the stores above are not eliminated.
    std::hint::black_box(ptr);
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Whether a block of `size` bytes is zeroed before it is freed right now.
fn wipes(size: usize) -> bool {
    size <= WIPE_MAX && active()
}

/// An allocator (the system one in the app) that zeroes small freed blocks while a
/// [`WipeScope`] is alive.
pub struct WipingAllocator<A = System>(A);

impl WipingAllocator {
    pub const fn new() -> Self {
        Self(System)
    }
}

impl Default for WipingAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every call forwards to the inner allocator with the same layouts; `realloc` of a wiped
// block is implemented as alloc + copy + wipe + dealloc, which `GlobalAlloc::realloc` permits.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live allocation of `layout.size()` bytes owned by the caller.
        unsafe {
            if wipes(layout.size()) {
                wipe(ptr, layout.size());
            }
            self.0.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged unless the old block is wiped; then the caller's
        // guarantees (live `ptr` of `layout`, valid `new_size` for `layout.align()`) make each
        // step sound. Decided by the *old* size: a small block growing past `WIPE_MAX` is still
        // wiped.
        unsafe {
            if !wipes(layout.size()) {
                return self.0.realloc(ptr, layout, new_size);
            }
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new = self.0.alloc(new_layout);
            if new.is_null() {
                return new;
            }
            std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            wipe(ptr, layout.size());
            self.0.dealloc(ptr, layout);
            new
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn scopes_nest() {
        let a = WipeScope::begin();
        let b = WipeScope::begin();
        assert!(active());
        drop(a);
        assert!(active());
        drop(b);
    }

    /// The system allocator, recording whether each block handed back to it was all zeroes
    /// (read while the block is still live, just before it is really freed).
    #[derive(Default)]
    struct Inspect(Mutex<Vec<(usize, bool)>>);

    // SAFETY: forwards to `System`; the extra read in `dealloc` is of a live block.
    unsafe impl GlobalAlloc for Inspect {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe {
                let zeroed = std::slice::from_raw_parts(ptr, layout.size()).iter().all(|b| *b == 0);
                self.0.lock().unwrap().push((layout.size(), zeroed));
                System.dealloc(ptr, layout);
            }
        }
    }

    impl Inspect {
        fn freed(&self) -> Vec<(usize, bool)> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    /// Allocates `size` bytes of 0xAA.
    unsafe fn filled(a: &WipingAllocator<Inspect>, size: usize) -> (*mut u8, Layout) {
        let layout = Layout::from_size_align(size, 8).unwrap();
        unsafe {
            let p = a.alloc(layout);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0xAA, size);
            (p, layout)
        }
    }

    #[test]
    fn freed_and_moved_small_blocks_are_zeroed_in_a_scope() {
        let a = WipingAllocator(Inspect::default());
        let _scope = WipeScope::begin();
        unsafe {
            let (p, layout) = filled(&a, 64);
            a.dealloc(p, layout);
            assert_eq!(a.0.freed(), [(64, true)]);

            // Growing a small block past `WIPE_MAX` still wipes the old one.
            let (p, layout) = filled(&a, 32);
            let q = a.realloc(p, layout, WIPE_MAX * 4);
            assert!(!q.is_null());
            assert_eq!(a.0.freed(), [(32, true)]);
            assert_eq!(std::slice::from_raw_parts(q, 32), [0xAA; 32]);
            a.dealloc(q, Layout::from_size_align(WIPE_MAX * 4, 8).unwrap());
            // Large blocks are left to the system allocator, untouched.
            assert_eq!(a.0.freed(), [(WIPE_MAX * 4, false)]);
        }
    }

    #[test]
    fn large_blocks_keep_the_fast_path_in_a_scope() {
        let a = WipingAllocator(Inspect::default());
        let _scope = WipeScope::begin();
        unsafe {
            let (p, layout) = filled(&a, WIPE_MAX + 1);
            a.dealloc(p, layout);
            // Realloc of a large block goes to the inner allocator's realloc (here the default
            // alloc + copy + dealloc, which frees the old block unwiped).
            let (p, layout) = filled(&a, WIPE_MAX + 1);
            let q = a.realloc(p, layout, WIPE_MAX * 2);
            assert_eq!(std::slice::from_raw_parts(q, WIPE_MAX + 1), vec![0xAA; WIPE_MAX + 1].as_slice());
            a.dealloc(q, Layout::from_size_align(WIPE_MAX * 2, 8).unwrap());
        }
        assert_eq!(a.0.freed(), [(WIPE_MAX + 1, false), (WIPE_MAX + 1, false), (WIPE_MAX * 2, false)]);
    }

    #[test]
    fn realloc_in_a_scope_keeps_the_contents() {
        let _scope = WipeScope::begin();
        let a = WipingAllocator::new();
        let layout = Layout::from_size_align(16, 8).unwrap();
        unsafe {
            let p = a.alloc(layout);
            assert!(!p.is_null());
            for i in 0..16 {
                *p.add(i) = i as u8 + 1;
            }
            let q = a.realloc(p, layout, 4096);
            assert!(!q.is_null());
            assert_eq!(std::slice::from_raw_parts(q, 16), (1..=16).collect::<Vec<u8>>().as_slice());
            let q = a.realloc(q, Layout::from_size_align(4096, 8).unwrap(), 8);
            assert_eq!(std::slice::from_raw_parts(q, 8), &[1, 2, 3, 4, 5, 6, 7, 8]);
            a.dealloc(q, Layout::from_size_align(8, 8).unwrap());
        }
    }

    #[test]
    fn wipe_zeroes_the_block() {
        let mut buf = *b"hunter2-password";
        unsafe { wipe(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf, [0; 16]);
    }
}
