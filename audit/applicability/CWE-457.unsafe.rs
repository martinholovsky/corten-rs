//@ compiles: unsafe
// CWE-457 in unsafe Rust: MaybeUninit::assume_init reads an uninitialised
// u32 (undefined behaviour).
use std::mem::MaybeUninit;
pub fn checksum() -> u32 {
    let sum = MaybeUninit::<u32>::uninit();
    unsafe { sum.assume_init() }
}
