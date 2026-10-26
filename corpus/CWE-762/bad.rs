//@ expect: -F unsafe-code
// CWE-762: releases memory with a routine that does not match its allocator.
use std::alloc::{Layout, dealloc};
fn main() {
    let p = Box::into_raw(Box::new(1u8));
    unsafe { dealloc(p, Layout::new::<u64>()) };
}
