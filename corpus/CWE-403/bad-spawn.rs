//@ expect: -F clippy::disallowed-methods
// CWE-403: spawns a child with ambient process authority, outside the
// broker that passes only declared handles.
fn main() {
    let status = std::process::Command::new("/bin/true").status();
    println!("{}", status.is_ok());
}
