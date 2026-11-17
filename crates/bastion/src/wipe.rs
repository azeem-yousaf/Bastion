//! Wiping freed memory while a password is being typed.
//!
//! egui's `TextEdit` copies the text it edits (masked or not) on every frame: `prev_text`, undo
//! snapshots, and the `Event::Text`/`Event::Paste`/IME strings that delivered each keystroke.
//! Those copies are freed without being cleared, so the password would linger on the heap. While
//! a [`WipeScope`] is alive, [`WipingAllocator`] (the app's global allocator) zeroes every
//! allocation before it is freed, and moves reallocations itself so the old block is zeroed too.
//! Outside a scope it is the system allocator plus one relaxed atomic load per free.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static SCOPES: AtomicUsize = AtomicUsize::new(0);

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
}

/// The system allocator, zeroing freed memory while a [`WipeScope`] is alive.
pub struct WipingAllocator;

// SAFETY: every call forwards to `System` with the same layouts; `realloc` in a scope is
// implemented as alloc + copy + wipe + dealloc, which `GlobalAlloc::realloc` permits.
unsafe impl GlobalAlloc for WipingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live allocation of `layout.size()` bytes owned by the caller.
        unsafe {
            if active() {
                wipe(ptr, layout.size());
            }
            System.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged outside a scope; inside one, the caller's guarantees
        // (live `ptr` of `layout`, valid `new_size` for `layout.align()`) make each step sound.
        unsafe {
            if !active() {
                return System.realloc(ptr, layout, new_size);
            }
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new = System.alloc(new_layout);
            if new.is_null() {
                return new;
            }
            std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            wipe(ptr, layout.size());
            System.dealloc(ptr, layout);
            new
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_nest() {
        let a = WipeScope::begin();
        let b = WipeScope::begin();
        assert!(active());
        drop(a);
        assert!(active());
        drop(b);
    }

    #[test]
    fn realloc_in_a_scope_keeps_the_contents() {
        let _scope = WipeScope::begin();
        let layout = Layout::from_size_align(16, 8).unwrap();
        unsafe {
            let p = WipingAllocator.alloc(layout);
            assert!(!p.is_null());
            for i in 0..16 {
                *p.add(i) = i as u8 + 1;
            }
            let q = WipingAllocator.realloc(p, layout, 4096);
            assert!(!q.is_null());
            assert_eq!(std::slice::from_raw_parts(q, 16), (1..=16).collect::<Vec<u8>>().as_slice());
            let q = WipingAllocator.realloc(q, Layout::from_size_align(4096, 8).unwrap(), 8);
            assert_eq!(std::slice::from_raw_parts(q, 8), &[1, 2, 3, 4, 5, 6, 7, 8]);
            WipingAllocator.dealloc(q, Layout::from_size_align(8, 8).unwrap());
        }
    }

    #[test]
    fn wipe_zeroes_the_block() {
        let mut buf = *b"hunter2-password";
        unsafe { wipe(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf, [0; 16]);
    }
}
