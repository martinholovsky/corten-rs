//@ expect: -F unsafe-code
// CWE-832: unlocks a lock that is no longer held.
use std::sync::Mutex;
fn main() {
    let m = Mutex::new(0u32);
    let guard = m.lock();
    let stale = unsafe { std::ptr::read(&raw const guard) };
    drop(guard);
    drop(stale);
}
