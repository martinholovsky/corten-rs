//@ compiles: safe
// CWE-820, missing synchronization: Send/Sync guard in-memory data, not
// external resources; two threads read-modify-write the same counter file
// with no lock.
use std::{fs, thread};
fn bump() {
    let n: u64 = fs::read_to_string("counter").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let _ = fs::write("counter", (n + 1).to_string());
}
pub fn run() {
    let t = thread::spawn(bump);
    bump();
    let _ = t.join();
}
