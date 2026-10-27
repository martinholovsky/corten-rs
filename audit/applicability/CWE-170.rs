//@ rejected: requires unsafe
// CWE-170, improper null termination. Rust strings carry their length and
// CString::new always appends the NUL; reading a buffer as a C string through
// a pointer (CStr::from_ptr) is an unsafe call, so safe code cannot do it.
use std::ffi::CStr;
pub fn name(buf: &[u8; 8]) -> &CStr {
    CStr::from_ptr(buf.as_ptr().cast())
}
