//@ compiles: unsafe
// CWE-403, file descriptor leak to a child. Clearing FD_CLOEXEC (F_SETFD=2)
// on the secret key's descriptor before spawn hands it to the untrusted
// plugin; only possible through an unsafe FFI call.
use std::os::fd::AsRawFd;
unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}
pub fn run_plugin() -> std::io::Result<()> {
    let secret = std::fs::File::open("/etc/app/secret.key")?;
    unsafe { fcntl(secret.as_raw_fd(), 2, 0) };
    std::process::Command::new("/opt/untrusted/plugin").spawn()?;
    Ok(())
}
