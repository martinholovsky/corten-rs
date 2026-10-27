//@ compiles: safe
// CWE-362, race condition: check and update are separate atomic operations,
// so two concurrent withdrawals can both pass the check (no data race, but a
// logical race Send/Sync do not prevent).
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
pub static BALANCE: AtomicU64 = AtomicU64::new(100);
pub fn withdraw(amount: u64) -> bool {
    let b = BALANCE.load(SeqCst);
    if b >= amount {
        BALANCE.store(b - amount, SeqCst);
        true
    } else {
        false
    }
}
