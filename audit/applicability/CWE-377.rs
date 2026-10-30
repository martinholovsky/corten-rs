//@ compiles: safe
// CWE-377, insecure temporary file. A predictable name in the shared temp
// directory is opened with File::create, which follows a pre-planted symlink
// and truncates its target (no O_EXCL).
use std::io::Write;
pub fn spill(data: &[u8]) -> std::io::Result<()> {
    let p = std::env::temp_dir().join("myapp.tmp");
    std::fs::File::create(p)?.write_all(data)
}
