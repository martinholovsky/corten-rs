//@ expect: -F unsafe-code
// CWE-824: reads through a pointer that was never initialised.
use std::mem::MaybeUninit;
fn main() {
    let p: *const u32 = unsafe { MaybeUninit::uninit().assume_init() };
    let v = unsafe { *p };
    println!("{v}");
}
