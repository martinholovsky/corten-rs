//@ compiles: unsafe
// CWE-828, handler with non-async-safe functionality: the handler allocates and
// writes a log file.
use std::ffi::c_int;
unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}
extern "C" fn on_signal(_: c_int) {
    let _ = std::fs::write("/tmp/crash.log", format!("signal at {:?}", std::time::SystemTime::now()));
}
pub fn install() {
    unsafe { signal(11, on_signal as usize) };
}
