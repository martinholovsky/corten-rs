//@ compiles: safe
// CWE-585, empty synchronized block: the lock that serializes log appends is
// taken and released in an empty block, so the write is unprotected.
use std::io::Write;
use std::sync::Mutex;
static LOG_LOCK: Mutex<()> = Mutex::new(());
pub fn append(path: &str, line: &str) -> std::io::Result<()> {
    {
        let _g = LOG_LOCK.lock().unwrap();
    }
    std::fs::OpenOptions::new().append(true).open(path)?.write_all(line.as_bytes())
}
