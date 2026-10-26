//@ expect: -F unsafe-code
// CWE-463: overwrites the terminating NUL, then reads the string.
use std::ffi::CStr;
fn main() {
    let mut buf = *b"ab\0";
    let p = buf.as_mut_ptr();
    unsafe { p.add(2).write(b'x') };
    let s = unsafe { CStr::from_ptr(p.cast()) };
    println!("{s:?}");
}
