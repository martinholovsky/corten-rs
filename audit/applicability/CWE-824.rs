//@ compiles: unsafe
// CWE-824, access of uninitialized pointer: an uninitialised pointer is
// assumed initialised and dereferenced.
use std::mem::MaybeUninit;
pub fn read() -> u8 {
    let p: *const u8 = unsafe { MaybeUninit::uninit().assume_init() };
    unsafe { *p }
}
