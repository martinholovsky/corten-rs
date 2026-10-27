//@ rejected: E0133
// CWE-364 attempted in safe Rust: std has no signal API; installing a handler
// is an FFI call to signal/sigaction, which safe code may not make.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
extern "C" fn on_signal(_: c_int) {}
pub fn install() {
    signal(2, on_signal as usize);
}
