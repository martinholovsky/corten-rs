//@ compiles: safe
// CWE-22, path traversal. User input joined under a base directory is read
// without canonicalising and checking the prefix, so "../../etc/passwd"
// escapes the directory.
use std::path::Path;
pub fn read_upload(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(Path::new("/srv/uploads").join(name))
}
