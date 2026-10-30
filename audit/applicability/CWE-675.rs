//@ compiles: safe
// CWE-675, operation repeated in a single-operation context: locking the
// same Mutex twice on one thread deadlocks or panics (std docs).
use std::sync::Mutex;
pub fn add(m: &Mutex<u64>, n: u64) -> u64 {
    let a = m.lock().unwrap();
    let b = m.lock().unwrap();
    *a + *b + n
}
