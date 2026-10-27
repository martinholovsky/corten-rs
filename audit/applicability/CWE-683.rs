//@ compiles: safe
// CWE-683, arguments in wrong order: fs::copy(from, to) called with the
// backup as source overwrites the live file.
use std::path::Path;
pub fn backup(live: &Path, bak: &Path) -> std::io::Result<u64> {
    std::fs::copy(bak, live)
}
