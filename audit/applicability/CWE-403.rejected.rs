//@ rejected: requires unsafe
// CWE-403, file descriptor leak to a child. std opens every descriptor with
// O_CLOEXEC, so the only way to let a child inherit one is to clear the flag
// via the OS (fcntl), and calling that foreign function needs unsafe.
use std::os::fd::AsRawFd;
unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}
pub fn run_plugin() -> std::io::Result<()> {
    let secret = std::fs::File::open("/etc/app/secret.key")?;
    fcntl(secret.as_raw_fd(), 2, 0);
    std::process::Command::new("/opt/untrusted/plugin").spawn()?;
    Ok(())
}
