//@ compiles: safe
// CWE-833, deadlock: two functions take the same two mutexes in opposite
// order; run concurrently they block forever.
use std::sync::Mutex;
pub fn a_to_b(a: &Mutex<u64>, b: &Mutex<u64>) {
    let _x = a.lock();
    let _y = b.lock();
}
pub fn b_to_a(a: &Mutex<u64>, b: &Mutex<u64>) {
    let _y = b.lock();
    let _x = a.lock();
}
