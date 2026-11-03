#![forbid(unsafe_code)]
// CWE-403 through nix: clear FD_CLOEXEC with the safe fcntl wrapper.
use std::os::fd::AsRawFd;
fn main() {
    let f = std::fs::File::open("/etc/hosts").unwrap();
    nix::fcntl::fcntl(&f, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty())).unwrap();
    let fd = f.as_raw_fd();
    let out = std::process::Command::new("sh")
        .arg("-c").arg(format!("head -c 20 <&{fd} >/dev/null && echo child-read-fd-{fd}"))
        .output().unwrap();
    print!("{}", String::from_utf8_lossy(&out.stdout));
}
