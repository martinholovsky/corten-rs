//@ compiles: safe
// CWE-363, race enabling link following: the symlink check and the write are
// separate syscalls; an attacker swaps in a symlink between them.
use std::{fs, io, path::Path};
pub fn write_report(path: &Path, data: &[u8]) -> io::Result<()> {
    if fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return Err(io::Error::other("symlink"));
    }
    fs::write(path, data)
}
