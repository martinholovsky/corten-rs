//@ compiles: safe
// CWE-391, unchecked error condition: `.ok()` drops the error from tightening
// permissions on a key file.
use std::os::unix::fs::PermissionsExt;
pub fn protect(key: &std::path::Path) {
    std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).ok();
}
