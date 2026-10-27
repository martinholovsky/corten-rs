//@ compiles: safe
// CWE-732, incorrect permission assignment for a critical resource: the
// private key file is made readable by every local user (0o644).
use std::os::unix::fs::PermissionsExt;
pub fn write_private_key(path: &str, key: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, key)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}
