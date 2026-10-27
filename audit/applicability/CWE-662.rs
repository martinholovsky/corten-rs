//@ compiles: safe
// CWE-662, improper synchronisation. Check and update take the lock
// separately, so two threads can both pass the balance check. No data race
// (safe Rust forbids those), but a race condition all the same.
use std::sync::Mutex;
pub fn withdraw(balance: &Mutex<u64>, amount: u64) -> bool {
    if *balance.lock().unwrap() >= amount {
        let mut b = balance.lock().unwrap();
        *b = b.wrapping_sub(amount);
        true
    } else {
        false
    }
}
