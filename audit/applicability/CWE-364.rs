//@ compiles: unsafe
// CWE-364, signal handler race: the handler and the main path both mutate a
// shared static; a signal between the main path's read and write corrupts it.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
static mut PENDING: u32 = 0;
extern "C" fn on_signal(_: c_int) {
    unsafe { PENDING += 1 };
}
pub fn run() {
    unsafe {
        signal(2, on_signal as usize);
        let p = PENDING;
        PENDING = p.saturating_sub(1);
    }
}
