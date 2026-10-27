//@ rejected: E0133
// CWE-432 attempted in safe Rust: installing any signal handler needs the
// unsafe FFI call; std offers no signal API.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
extern "C" fn on_signal(_: c_int) {}
pub fn install() {
    signal(2, on_signal as usize);
}
