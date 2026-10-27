//@ compiles: unsafe
// CWE-111 (unsafe JNI), Rust analog: FFI. Calling foreign C code hands
// control to code whose memory errors Rust cannot check; strcpy here can
// overflow the 8-byte `dst`. Declaring and calling foreign code needs unsafe.
use std::ffi::{CStr, c_char};
unsafe extern "C" {
    fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char;
}
pub fn copy(dst: &mut [u8; 8], src: &CStr) {
    unsafe {
        strcpy(dst.as_mut_ptr().cast(), src.as_ptr());
    }
}
