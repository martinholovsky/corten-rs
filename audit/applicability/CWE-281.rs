//@ compiles: safe
// CWE-281, improper preservation of permissions: a backup is made by creating
// a new file and streaming the bytes, so a 0600 source becomes a file with the
// default (umask-derived, usually 0644) mode.
pub fn backup(src: &str, dst: &str) -> std::io::Result<u64> {
    let mut from = std::fs::File::open(src)?;
    let mut to = std::fs::File::create(dst)?;
    std::io::copy(&mut from, &mut to)
}
