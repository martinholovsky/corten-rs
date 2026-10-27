//@ expect: -F unsafe-code
// CWE-765: unlocks the same lock twice.
use std::sync::Mutex;
fn main() {
    let m = Mutex::new(0u32);
    let guard = m.lock();
    let copy = unsafe { std::ptr::read(&raw const guard) };
    drop(guard);
    drop(copy);
}
