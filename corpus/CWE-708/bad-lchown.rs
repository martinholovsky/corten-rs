//@ expect: -F clippy::disallowed-methods
// CWE-708 variant: the link itself, not its target.
fn main() {
    let _r = std::os::unix::fs::lchown("upload.dat", Some(65534), None);
}
