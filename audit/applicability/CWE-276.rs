//@ compiles: safe
// CWE-276, incorrect default permissions: the installer writes the program
// file world-writable (0o777).
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
pub fn install(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).mode(0o777).open(path)?;
    f.write_all(bytes)
}
