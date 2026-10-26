//@ expect: -F clippy::disallowed-methods
// CWE-378: a temporary file with a predictable name and default mode.
use std::io::Write;
fn main() {
    let path = std::env::temp_dir().join("report.tmp");
    if let Ok(mut f) = std::fs::File::create(path) {
        let _w = f.write_all(b"draft");
    }
}
