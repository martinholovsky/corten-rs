//@ compiles: safe
// CWE-772, missing release of a resource. Forgetting a MutexGuard is safe and
// never unlocks the mutex, so every later lock() blocks for ever.
use std::sync::Mutex;
pub fn touch(m: &Mutex<u32>) {
    let g = m.lock().unwrap();
    std::mem::forget(g);
}
