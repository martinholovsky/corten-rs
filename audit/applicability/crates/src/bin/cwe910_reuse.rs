#![forbid(unsafe_code)]
// CWE-910: close a File's descriptor by number; the number is reused by the
// next open, and the stale File then reads the other file.
use std::io::Read;
use std::os::fd::AsRawFd;
fn main() {
    let mut stale = std::fs::File::open("/etc/hosts").unwrap();
    nix::unistd::close(stale.as_raw_fd()).unwrap();
    let fresh = std::fs::File::open("/etc/shells").unwrap();
    println!("stale fd {} fresh fd {}", stale.as_raw_fd(), fresh.as_raw_fd());
    let mut s = String::new();
    stale.read_to_string(&mut s).unwrap();
    println!("stale File read: {:?}", s.lines().next());
    std::mem::forget(fresh);
}
