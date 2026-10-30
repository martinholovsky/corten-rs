//@ rejected: E0133
// CWE-558 attempted in safe Rust: std has no getlogin; calling the libc
// function is an unsafe FFI call.
use std::ffi::c_char;
unsafe extern "C" {
    fn getlogin() -> *const c_char;
}
pub fn who() -> *const c_char {
    getlogin()
}
