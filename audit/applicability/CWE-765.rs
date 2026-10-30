//@ compiles: safe
// CWE-765, multiple unlocks: std's RAII guards unlock exactly once, but a
// hand-rolled lock with an explicit release can be released twice, admitting
// two holders.
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
pub struct Slots(pub AtomicUsize);
impl Slots {
    pub fn acquire(&self) -> bool {
        self.0.fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1)).is_ok()
    }
    pub fn release(&self) { self.0.fetch_add(1, SeqCst); }
}
pub fn job(s: &Slots) {
    if s.acquire() {
        s.release();
    }
    s.release();
}
