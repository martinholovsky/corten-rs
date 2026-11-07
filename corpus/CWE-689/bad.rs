//@ expect: -F clippy::disallowed-methods
// CWE-689: copy a secret, then restrict the copy. Until set_permissions runs, the copy
// carries whatever mode the copy gave it.
use std::os::unix::fs::PermissionsExt;
fn main() {
    if std::fs::copy("secret.key", "backup.key").is_ok() {
        let _r = std::fs::set_permissions("backup.key", std::fs::Permissions::from_mode(0o600));
    }
}
