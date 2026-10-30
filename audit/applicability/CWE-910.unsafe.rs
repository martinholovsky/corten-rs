//@ compiles: unsafe
// CWE-910 in unsafe Rust: the fd is closed by drop and then wrapped again;
// the number may by now name a different, newly opened file.
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
pub fn reuse(p: &str) -> std::io::Result<File> {
    let f = File::open(p)?;
    let fd = f.as_raw_fd();
    drop(f);
    Ok(unsafe { File::from_raw_fd(fd) })
}
