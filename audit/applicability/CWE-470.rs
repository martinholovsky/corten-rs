//@ rejected: is unsafe and requires unsafe block
// CWE-470, externally controlled selection of code. Rust has no reflection;
// selecting code by a runtime name means dlsym plus a transmute to a fn
// pointer, which safe Rust refuses (E0133).
use std::ffi::{CString, c_char, c_void};
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
pub fn lookup(name_from_request: &str) -> *mut c_void {
    let c = CString::new(name_from_request).unwrap();
    dlsym(std::ptr::null_mut(), c.as_ptr())
}
