//@ expect: interior
// CWE-493 through interior mutability. Caught by the interior-mutable-pub-
// static lint (corten-driver, Phase 3b).
use std::sync::atomic::{AtomicU32, Ordering};
pub static LIMIT: AtomicU32 = AtomicU32::new(10);
fn main() {
    LIMIT.store(1_000_000, Ordering::Relaxed);
    println!("{}", LIMIT.load(Ordering::Relaxed));
}
