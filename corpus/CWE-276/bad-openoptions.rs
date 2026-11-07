//@ expect: -F clippy::disallowed-types
// CWE-276 variant: an explicit world-writable creation mode.
use std::os::unix::fs::OpenOptionsExt;
fn main() {
    let _f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open("shared.conf");
}
