//@ compiles: safe
// CWE-689, permission race during copy: the copy is created with default
// (umask) permissions and only restricted afterwards, leaving a window.
use std::os::unix::fs::PermissionsExt;
use std::{fs, io, path::Path};
pub fn copy_secret(src: &Path, dst: &Path) -> io::Result<()> {
    fs::write(dst, fs::read(src)?)?;
    fs::set_permissions(dst, fs::Permissions::from_mode(0o600))
}
