//@ compiles: unsafe
// CWE-242, inherently dangerous function: gets() cannot bound its write.
// std has no such function; reaching libc's gets needs an unsafe call.
use std::ffi::c_char;
unsafe extern "C" {
    fn gets(buf: *mut c_char) -> *mut c_char;
}
pub fn read_line(buf: &mut [u8; 64]) {
    unsafe {
        gets(buf.as_mut_ptr().cast());
    }
}
