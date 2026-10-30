//@ compiles: safe
// CWE-764, multiple locks of a critical resource: the same thread locks a std
// Mutex twice; std documents this may deadlock or panic.
use std::sync::Mutex;
pub fn transfer(m: &Mutex<u64>) {
    let _a = m.lock();
    let _b = m.lock();
}
