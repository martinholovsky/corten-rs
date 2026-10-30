//@ compiles: unsafe
// CWE-831, one handler function associated with multiple signals: the same
// non-reentrant handler serves SIGHUP and SIGTERM.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
static mut STATE: Vec<u8> = Vec::new();
extern "C" fn handler(_: c_int) {
    unsafe { (*(&raw mut STATE)).clear() };
}
pub fn install() {
    unsafe {
        signal(1, handler as usize);
        signal(15, handler as usize);
    }
}
