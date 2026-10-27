//@ compiles: safe
// CWE-1096, singleton created without proper synchronization: get-then-set on
// a OnceLock lets two threads both construct the instance (side effects run
// twice); statics must be Sync, so the slot itself cannot data-race.
use std::sync::OnceLock;
pub struct Pool { pub id: u64 }
static POOL: OnceLock<Pool> = OnceLock::new();
fn connect() -> Pool { Pool { id: 1 } }
pub fn pool() -> &'static Pool {
    if POOL.get().is_none() {
        let _ = POOL.set(connect());
    }
    POOL.get().unwrap_or_else(|| unreachable!())
}
