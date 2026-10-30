//@ compiles: unsafe
// CWE-470 in unsafe Rust: the request names a symbol, dlsym resolves it and
// it is called, so any exported function is reachable. The handle is a stub.
use std::ffi::{CString, c_char, c_void};
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
pub fn call_by_name(name_from_request: &str) {
    let c = CString::new(name_from_request).unwrap();
    unsafe {
        let p = dlsym(std::ptr::null_mut(), c.as_ptr());
        if !p.is_null() {
            let f: extern "C" fn() = std::mem::transmute(p);
            f();
        }
    }
}
