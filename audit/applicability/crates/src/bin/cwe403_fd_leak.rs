#![forbid(unsafe_code)]
// CWE-403: clear close-on-exec on a secret file, then run a child.
use std::os::fd::AsRawFd;
fn main() {
    let f = std::fs::File::open("/etc/hosts").unwrap();
    rustix::io::fcntl_setfd(&f, rustix::io::FdFlags::empty()).unwrap();
    let fd = f.as_raw_fd();
    let out = std::process::Command::new("sh")
        .arg("-c").arg(format!("head -c 20 <&{fd} >/dev/null && echo child-read-fd-{fd}"))
        .output().unwrap();
    print!("{}", String::from_utf8_lossy(&out.stdout));
}
