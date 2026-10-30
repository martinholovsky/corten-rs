//@ compiles: safe
// CWE-821, incorrect synchronization: the balance is locked for the check and
// again for the update, so the critical section is split and two callers can
// both pass the check.
use std::sync::Mutex;
pub fn withdraw(bal: &Mutex<u64>, amount: u64) -> bool {
    let ok = bal.lock().map(|b| *b >= amount).unwrap_or(false);
    if ok {
        if let Ok(mut b) = bal.lock() { *b = b.saturating_sub(amount); }
    }
    ok
}
