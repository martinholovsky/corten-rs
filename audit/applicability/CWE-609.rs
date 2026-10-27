//@ compiles: safe
// CWE-609, double-checked locking with relaxed atomics: a reader may see READY
// set yet still read the old VALUE, because Relaxed gives no happens-before.
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
static READY: AtomicBool = AtomicBool::new(false);
static VALUE: AtomicU64 = AtomicU64::new(0);
static INIT: Mutex<()> = Mutex::new(());
pub fn get() -> u64 {
    if !READY.load(Relaxed) {
        let _g = INIT.lock();
        if !READY.load(Relaxed) {
            VALUE.store(42, Relaxed);
            READY.store(true, Relaxed);
        }
    }
    VALUE.load(Relaxed)
}
