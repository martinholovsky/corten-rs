//@ compiles: safe
// CWE-667, improper locking: the guard is forgotten instead of dropped, so the
// mutex is never released and every later caller blocks.
use std::sync::Mutex;
pub static CACHE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub fn fill(data: &[u8]) {
    if let Ok(mut g) = CACHE.lock() {
        g.extend_from_slice(data);
        std::mem::forget(g);
    }
}
