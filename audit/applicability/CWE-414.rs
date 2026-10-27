//@ compiles: safe
// CWE-414, missing lock check: maintenance mode is the lock other writers
// respect, but reset_accounts never checks it.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
pub static MIGRATION_LOCKED: AtomicBool = AtomicBool::new(false);
pub fn reset_accounts(accounts: &mut Vec<u64>) {
    accounts.iter_mut().for_each(|a| *a = 0);
}
pub fn deposit(accounts: &mut [u64], i: usize, v: u64) {
    if !MIGRATION_LOCKED.load(SeqCst) { accounts[i] += v; }
}
