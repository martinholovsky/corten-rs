//@ compiles: safe
// CWE-691, insufficient control flow management: `?` returns early on error
// and skips clearing the maintenance flag, leaving the service locked open.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
pub static MAINTENANCE: AtomicBool = AtomicBool::new(false);
pub fn migrate(step: impl Fn() -> std::io::Result<()>) -> std::io::Result<()> {
    MAINTENANCE.store(true, SeqCst);
    step()?;
    MAINTENANCE.store(false, SeqCst);
    Ok(())
}
