//@ rejected: E0133
// CWE-762 attempted in safe Rust: Drop always pairs an allocation with its own
// deallocator; calling dealloc by hand requires unsafe.
use std::alloc::{alloc, dealloc, Layout};
pub fn mismatch() {
    let l = Layout::new::<u64>();
    let p = alloc(l);
    dealloc(p, Layout::new::<u8>());
}
