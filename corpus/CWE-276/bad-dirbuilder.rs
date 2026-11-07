//@ expect: -F clippy::disallowed-types
// CWE-276 variant: a world-writable directory.
use std::os::unix::fs::DirBuilderExt;
fn main() {
    let _r = std::fs::DirBuilder::new().mode(0o777).create("spool");
}
