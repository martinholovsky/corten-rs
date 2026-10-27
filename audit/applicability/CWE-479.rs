//@ compiles: unsafe
// CWE-479, signal handler calls a non-reentrant function: println! takes the
// stdout lock and allocates, neither async-signal-safe.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
extern "C" fn on_signal(_: c_int) {
    println!("caught signal");
}
pub fn install() {
    unsafe { signal(2, on_signal as usize) };
}
