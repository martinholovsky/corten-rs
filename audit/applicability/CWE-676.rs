//@ compiles: safe
// CWE-676, potentially dangerous function: Path::join with an absolute
// argument replaces the base, so "/etc/passwd" escapes the upload dir. Safe,
// but dangerous with untrusted input.
use std::path::{Path, PathBuf};
pub fn upload_path(user_name: &str) -> PathBuf {
    Path::new("/srv/uploads").join(user_name)
}
