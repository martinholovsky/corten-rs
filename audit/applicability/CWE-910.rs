//@ rejected: is unsafe and requires unsafe block
// CWE-910, use of an expired file descriptor. Turning a raw fd number back
// into a File is unsafe by Rust's I/O-safety rules, so safe code cannot use
// a descriptor after the File owning it closed it (E0133).
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
pub fn reuse(p: &str) -> std::io::Result<File> {
    let f = File::open(p)?;
    let fd = f.as_raw_fd();
    drop(f);
    Ok(File::from_raw_fd(fd))
}
