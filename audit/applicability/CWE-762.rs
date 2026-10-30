//@ compiles: unsafe
// CWE-762, mismatched memory management routines: memory allocated with one
// layout is released through dealloc with another.
use std::alloc::{alloc, dealloc, Layout};
pub fn mismatch() {
    unsafe {
        let p = alloc(Layout::from_size_align_unchecked(64, 8));
        dealloc(p, Layout::from_size_align_unchecked(16, 1));
    }
}
