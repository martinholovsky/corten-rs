//@ compiles: safe
// CWE-500, public static field not final. A plain `pub static` is immutable,
// but one of an interior-mutable type is a writable global in safe Rust.
use std::sync::atomic::{AtomicBool, Ordering};
pub static DEBUG_BYPASS_AUTH: AtomicBool = AtomicBool::new(false);
pub fn anyone() {
    DEBUG_BYPASS_AUTH.store(true, Ordering::Relaxed);
}
