//@ expect: -F clippy::disallowed-methods
// CWE-276: a new file at the process default mode (0666 less the umask), which a
// permissive umask leaves writable by anyone.
use std::io::Write;
fn main() {
    if let Ok(mut f) = std::fs::File::create("shared.conf") {
        let _w = f.write_all(b"key=value");
    }
}
