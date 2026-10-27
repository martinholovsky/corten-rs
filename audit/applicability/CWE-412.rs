//@ compiles: safe
// CWE-412, externally accessible lock: the lock is a file in world-writable
// /tmp; any local user can create it and stop the service.
use std::path::Path;
pub fn try_start() -> bool {
    let lock = Path::new("/tmp/backup.lock");
    if lock.exists() {
        return false;
    }
    std::fs::write(lock, b"1").is_ok()
}
