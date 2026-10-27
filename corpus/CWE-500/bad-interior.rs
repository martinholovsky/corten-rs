//@ expect: interior
// CWE-500 through interior mutability (corten-driver lint, see 493).
use std::sync::atomic::{AtomicU32, Ordering};
pub static RETRIES: AtomicU32 = AtomicU32::new(3);
fn main() {
    RETRIES.store(0, Ordering::Relaxed);
    println!("{}", RETRIES.load(Ordering::Relaxed));
}
