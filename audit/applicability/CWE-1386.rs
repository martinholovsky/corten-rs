//@ compiles: safe
// CWE-1386, insecure operation on a junction/mount point. The check and the
// recursive delete use the path separately; a junction swapped in between
// redirects the delete outside the intended directory.
use std::fs;
pub fn purge(dir: &str) -> std::io::Result<()> {
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Ok(());
    }
    fs::remove_dir_all(dir)
}
