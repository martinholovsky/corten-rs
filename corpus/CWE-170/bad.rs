//@ expect: -F unsafe-code
// CWE-170: treats bytes with no terminating NUL as a C string.
use std::ffi::CStr;
fn main() {
    let raw: &[u8] = b"abc";
    let s = unsafe { CStr::from_bytes_with_nul_unchecked(raw) };
    println!("{s:?}");
}
