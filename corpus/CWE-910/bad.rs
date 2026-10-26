//@ expect: -F unsafe-code
// CWE-910: uses a file descriptor after it was closed.
use std::os::fd::{FromRawFd, OwnedFd};
fn main() {
    let a = unsafe { OwnedFd::from_raw_fd(1) };
    drop(a);
    let b = unsafe { OwnedFd::from_raw_fd(1) };
    println!("{b:?}");
}
