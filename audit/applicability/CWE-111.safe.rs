//@ rejected: extern blocks must be unsafe
// CWE-111 analog: the same foreign call written without `unsafe` is refused;
// edition 2024 requires `unsafe extern` for any foreign declaration.
use std::ffi::{CStr, c_char};
extern "C" {
    fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char;
}
pub fn copy(dst: &mut [u8; 8], src: &CStr) {
    strcpy(dst.as_mut_ptr().cast(), src.as_ptr());
}
