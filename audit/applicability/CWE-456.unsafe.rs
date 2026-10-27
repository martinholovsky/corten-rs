//@ compiles: unsafe
// CWE-456 in unsafe Rust: assume_init on MaybeUninit skips initialisation,
// so `limit` holds whatever was on the stack (undefined behaviour).
use std::mem::MaybeUninit;
pub fn limit_for(premium: bool) -> u32 {
    let mut limit: u32 = unsafe { MaybeUninit::uninit().assume_init() };
    if premium {
        limit = 100;
    }
    limit
}
