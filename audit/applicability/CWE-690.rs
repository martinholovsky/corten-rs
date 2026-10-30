//@ compiles: unsafe
// CWE-690, unchecked return value to NULL dereference: std::alloc::alloc
// returns null on failure and the result is written without a check.
use std::alloc::{alloc, Layout};
pub fn make(n: usize) -> *mut u8 {
    let layout = Layout::array::<u8>(n).unwrap_or(Layout::new::<u8>());
    let p = unsafe { alloc(layout) };
    unsafe { *p = 1 };
    p
}
