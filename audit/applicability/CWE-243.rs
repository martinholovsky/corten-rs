//@ compiles: safe
// CWE-243, chroot jail without changing the working directory. std's safe
// std::os::unix::fs::chroot does not chdir("/"), so the cwd stays outside the
// jail and relative paths escape it.
use std::os::unix::fs::chroot;
pub fn jail_and_read() -> std::io::Result<String> {
    chroot("/var/jail")?;
    std::fs::read_to_string("../../etc/shadow")
}
