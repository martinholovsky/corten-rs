//@ rejected: E0133
// CWE-763 attempted in safe Rust: releasing memory is the owner's Drop; an
// arbitrary pointer can reach dealloc only through unsafe.
use std::alloc::{dealloc, Layout};
pub fn release(addr: usize) {
    dealloc(addr as *mut u8, Layout::new::<u64>());
}
