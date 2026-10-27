//@ compiles: safe
// CWE-775, descriptor not released after its lifetime. Each audited file is
// pushed into a process-wide list that is never drained, so its handle stays
// open long after use.
use std::fs::File;
use std::sync::Mutex;
static OPENED: Mutex<Vec<File>> = Mutex::new(Vec::new());
pub fn audit(p: &str) -> std::io::Result<()> {
    let f = File::open(p)?;
    OPENED.lock().unwrap().push(f);
    Ok(())
}
