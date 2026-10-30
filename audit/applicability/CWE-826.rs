//@ compiles: safe
// CWE-826, premature release. The lock that serialises writers to the shared
// file is dropped before the write, so concurrent writers interleave.
use std::sync::Mutex;
pub fn append(lock: &Mutex<()>, line: &str) -> std::io::Result<()> {
    let guard = lock.lock().unwrap();
    drop(guard);
    let old = std::fs::read_to_string("/var/log/app.log").unwrap_or_default();
    std::fs::write("/var/log/app.log", old + line)
}
