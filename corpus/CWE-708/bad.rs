//@ expect: -F clippy::disallowed-methods
// CWE-708: hand a file to another user.
fn main() {
    let _r = std::os::unix::fs::chown("upload.dat", Some(65534), Some(65534));
}
