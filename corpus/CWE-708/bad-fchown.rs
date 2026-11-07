//@ expect: -F clippy::disallowed-methods
// CWE-708 variant: ownership of an object the process already holds a descriptor for.
// Standard output implements AsFd, so no banned type is needed to reach fchown.
fn main() {
    let _r = std::os::unix::fs::fchown(std::io::stdout(), Some(65534), None);
}
