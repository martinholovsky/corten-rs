//@ compiles: safe
// CWE-773, missing reference to an active file descriptor. into_raw_fd is
// safe; discarding the integer it returns leaks the open descriptor.
use std::fs::File;
use std::os::fd::IntoRawFd;
pub fn probe(p: &str) -> std::io::Result<()> {
    let _ = File::open(p)?.into_raw_fd();
    Ok(())
}
