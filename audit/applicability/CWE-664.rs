//@ compiles: safe
// CWE-664, improper control of a resource through its lifetime. Box::leak is
// safe: every call opens a file whose handle can never be released.
use std::fs::File;
pub fn open_forever(p: &str) -> std::io::Result<&'static File> {
    Ok(Box::leak(Box::new(File::open(p)?)))
}
