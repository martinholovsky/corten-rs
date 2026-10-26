//@ expect: -F unsafe-code
// CWE-690: dereferences a possibly-null return value without a check.
use std::ffi::c_char;
unsafe extern "C" {
    fn getenv(name: *const c_char) -> *const c_char;
}
fn main() {
    let p = unsafe { getenv(c"CORTEN_NOT_SET".as_ptr()) };
    let first = unsafe { *p };
    println!("{first}");
}
