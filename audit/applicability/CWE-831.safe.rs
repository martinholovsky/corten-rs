//@ rejected: E0133
// CWE-831 attempted in safe Rust: registering the handler needs unsafe FFI.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
extern "C" fn on_signal(_: c_int) {}
pub fn install() {
    signal(2, on_signal as usize);
}
