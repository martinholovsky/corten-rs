//@ rejected: requires unsafe block
// CWE-785: calling realpath without unsafe is refused.
use std::ffi::{CStr, c_char};
unsafe extern "C" {
    fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char;
}
pub fn resolve(p: &CStr) -> [u8; 64] {
    let mut buf = [0u8; 64];
    realpath(p.as_ptr(), buf.as_mut_ptr().cast());
    buf
}
