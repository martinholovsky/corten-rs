//@ compiles: unsafe
// CWE-170, improper null termination. Eight name bytes fill the buffer and
// no terminator is written; CStr::from_ptr then reads past the end.
use std::ffi::CStr;
pub fn name(raw: &[u8; 8]) -> usize {
    let buf: [u8; 8] = *raw;
    unsafe { CStr::from_ptr(buf.as_ptr().cast()).to_bytes().len() }
}
