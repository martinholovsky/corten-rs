//@ compiles: unsafe
// CWE-1341, multiple releases of the same handle: two Files built from one
// raw fd each close it on drop.
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd};
pub fn close_twice(f: File) {
    let fd = f.into_raw_fd();
    unsafe {
        drop(File::from_raw_fd(fd));
        drop(File::from_raw_fd(fd));
    }
}
