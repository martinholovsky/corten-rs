//@ compiles: safe
// CWE-832, unlock of a resource that is not locked: a hand-rolled spin lock
// with explicit unlock is released on a path that never acquired it.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
pub struct SpinLock(pub AtomicBool);
impl SpinLock {
    pub fn try_lock(&self) -> bool { self.0.compare_exchange(false, true, SeqCst, SeqCst).is_ok() }
    pub fn unlock(&self) { self.0.store(false, SeqCst); }
}
pub fn work(l: &SpinLock) {
    let _ = l.try_lock();
    l.unlock();
}
