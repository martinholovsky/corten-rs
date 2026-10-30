//@ compiles: unsafe
// CWE-785: realpath() writes up to PATH_MAX bytes into a 64-byte buffer.
// std::fs::canonicalize returns an allocated PathBuf; libc's needs unsafe.
use std::ffi::{CStr, c_char};
unsafe extern "C" {
    fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char;
}
pub fn resolve(p: &CStr) -> [u8; 64] {
    let mut buf = [0u8; 64];
    unsafe {
        realpath(p.as_ptr(), buf.as_mut_ptr().cast());
    }
    buf
}
