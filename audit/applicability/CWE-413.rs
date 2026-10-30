//@ compiles: safe
// CWE-413, improper resource locking: the Mutex guards the journal file by
// convention only; append_fast writes without taking it. Mutex<T> protects T,
// not an external resource.
use std::{fs::OpenOptions, io::Write, sync::Mutex};
pub static JOURNAL_LOCK: Mutex<()> = Mutex::new(());
pub fn append(line: &str) {
    let _g = JOURNAL_LOCK.lock();
    append_fast(line);
}
pub fn append_fast(line: &str) {
    if let Ok(mut f) = OpenOptions::new().append(true).open("journal") {
        let _ = f.write_all(line.as_bytes());
    }
}
