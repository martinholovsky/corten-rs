//@ compiles: unsafe
// CWE-432, dangerous handler not disabled during sensitive operations: one
// handler for SIGINT and SIGTERM frees shared state, and neither signal is
// masked while it runs, so a second signal re-enters it.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
static mut BUF: Option<Vec<u8>> = None;
extern "C" fn cleanup(_: c_int) {
    unsafe { *(&raw mut BUF) = None };
}
pub fn install() {
    unsafe {
        signal(2, cleanup as usize);
        signal(15, cleanup as usize);
    }
}
