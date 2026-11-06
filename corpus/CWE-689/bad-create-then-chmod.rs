//@ expect: -F clippy::disallowed-methods
// CWE-689 variant: create at the default mode, write, then restrict.
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
fn main() {
    if let Ok(mut f) = std::fs::File::create("backup.key") {
        let _w = f.write_all(b"key material");
        let _r = std::fs::set_permissions("backup.key", std::fs::Permissions::from_mode(0o600));
    }
}
