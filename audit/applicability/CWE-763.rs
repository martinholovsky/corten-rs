//@ compiles: unsafe
// CWE-763, release of invalid pointer: a pointer that never came from the
// allocator is passed to dealloc.
use std::alloc::{dealloc, Layout};
pub fn release(addr: usize) {
    unsafe { dealloc(addr as *mut u8, Layout::new::<u64>()) };
}
