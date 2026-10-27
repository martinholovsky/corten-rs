//@ compiles: safe
// CWE-366, race condition within a thread: two threads each load, add and
// store a shared counter, losing updates.
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::thread;
pub static ISSUED: AtomicU64 = AtomicU64::new(0);
fn issue() {
    let n = ISSUED.load(Relaxed);
    ISSUED.store(n + 1, Relaxed);
}
pub fn run() {
    let t = thread::spawn(issue);
    issue();
    let _ = t.join();
}
