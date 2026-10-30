//@ compiles: safe
// CWE-378, temporary file created with insecure permissions: mode 0o666
// (subject only to umask) makes the secret world-readable.
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
pub fn spill(secret: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o666)
        .open("/tmp/myapp-secret.tmp")?;
    f.write_all(secret)
}
