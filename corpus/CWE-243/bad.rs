//@ expect: -F clippy::disallowed-methods
// CWE-243: chroot without changing the working directory.
fn main() {
    if let Err(e) = std::os::unix::fs::chroot("/srv/jail") {
        println!("{e}");
    }
}
