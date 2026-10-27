//@ expect: -F unsafe-code
// CWE-464: a NUL inside the data acts as an early terminator.
use std::ffi::CStr;
fn main() {
    let data = b"ab\0cd\0";
    let s = unsafe { CStr::from_ptr(data.as_ptr().cast()) };
    println!("{s:?}");
}
