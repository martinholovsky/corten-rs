//@ compiles: safe
// CWE-368, context switching race: the privilege level is process-global and
// raised for one task; another thread checking it during the switch runs with
// the raised privilege.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
pub static ELEVATED: AtomicBool = AtomicBool::new(false);
pub fn rotate_logs() {
    ELEVATED.store(true, SeqCst);
    // ... privileged work ...
    ELEVATED.store(false, SeqCst);
}
pub fn may_delete(_user_file: &str) -> bool {
    ELEVATED.load(SeqCst)
}
