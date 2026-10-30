//@ compiles: safe
// CWE-367, TOCTOU: checks the file does not exist, then creates it; between
// the two another process can create it (or a symlink) first.
use std::{fs::File, io, path::Path};
pub fn create_new(path: &Path) -> io::Result<File> {
    if path.exists() {
        return Err(io::Error::other("exists"));
    }
    File::create(path)
}
