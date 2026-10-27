//@ rejected: requires unsafe block
// CWE-242: calling the foreign gets() without an unsafe block is refused.
use std::ffi::c_char;
unsafe extern "C" {
    fn gets(buf: *mut c_char) -> *mut c_char;
}
pub fn read_line(buf: &mut [u8; 64]) {
    gets(buf.as_mut_ptr().cast());
}
