//@ compiles: unsafe
// CWE-558, getlogin() in a multithreaded program: it returns a pointer to a
// static buffer that a concurrent call overwrites.
use std::ffi::{c_char, CStr};
unsafe extern "C" {
    fn getlogin() -> *const c_char;
}
pub fn who() -> String {
    std::thread::spawn(|| unsafe { CStr::from_ptr(getlogin()) }.to_string_lossy().into_owned())
        .join()
        .unwrap_or_default()
}
