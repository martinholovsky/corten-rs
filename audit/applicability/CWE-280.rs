//@ compiles: safe
// CWE-280, improper handling of insufficient permissions: tightening a secret
// file's mode fails with PermissionDenied, the error is dropped, and the
// caller is told the file is protected.
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
pub fn protect(path: &str) -> bool {
    std::fs::set_permissions(path, Permissions::from_mode(0o600)).ok();
    true
}
