#![forbid(unsafe_code)]
// CWE-1341 / 910: close a descriptor by number, then use or close it again.
use std::os::fd::AsRawFd;
fn main() {
    let f = std::fs::File::open("/etc/hosts").unwrap();
    let raw = f.as_raw_fd();
    println!("first close: {:?}", nix::unistd::close(raw));
    println!("second close: {:?}", nix::unistd::close(raw));
}
