//@ expect: -F unsafe-code
// CWE-908: uses a buffer before initialising it.
use std::mem::MaybeUninit;
fn main() {
    let buf: [u8; 16] = unsafe { MaybeUninit::uninit().assume_init() };
    println!("{buf:?}");
}
