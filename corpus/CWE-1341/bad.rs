//@ expect: -F unsafe-code
// CWE-1341: releases the same handle twice.
use std::mem::ManuallyDrop;
fn main() {
    let mut v = ManuallyDrop::new(vec![1u8, 2]);
    unsafe {
        ManuallyDrop::drop(&mut v);
        ManuallyDrop::drop(&mut v);
    }
}
