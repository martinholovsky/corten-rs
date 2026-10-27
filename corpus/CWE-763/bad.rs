//@ expect: -F unsafe-code
// CWE-763: releases a pointer that was never allocated.
fn main() {
    let p = std::ptr::dangling_mut::<u32>();
    unsafe { drop(Box::from_raw(p)) };
}
