//@ compiles: safe
// CWE-386, symbolic name not mapping to the same object. The path is checked
// and then used by name again; between the calls it can be replaced by a
// symlink to another file.
use std::fs;
pub fn update(data: &str) -> std::io::Result<()> {
    let p = "/tmp/app.conf";
    if fs::symlink_metadata(p)?.file_type().is_symlink() {
        return Ok(());
    }
    fs::write(p, data)
}
