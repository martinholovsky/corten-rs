//@ compiles: safe
// CWE-686, argument of wrong type: generic drop() accepts &MutexGuard, so
// passing a reference compiles, drops nothing, and the lock stays held.
use std::sync::Mutex;
pub fn update(m: &Mutex<Vec<u8>>, slow: impl FnOnce()) {
    let mut g = m.lock().unwrap();
    g.push(1);
    #[allow(dropping_references)]
    drop(&g);
    slow();
}
