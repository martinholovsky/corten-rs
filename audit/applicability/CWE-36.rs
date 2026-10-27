//@ compiles: safe
// CWE-36, absolute path traversal. std's Path::join replaces the base when
// the argument is absolute, so join("/etc/shadow") reads /etc/shadow.
use std::path::Path;
pub fn read_doc(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(Path::new("/srv/docs").join(name))
}
