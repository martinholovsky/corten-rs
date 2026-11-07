//@ expect: -F clippy::disallowed-methods
// CWE-276 variant: widening a file's mode after the fact.
use std::os::unix::fs::PermissionsExt;
fn main() {
    let _r = std::fs::set_permissions("shared.conf", std::fs::Permissions::from_mode(0o666));
}
