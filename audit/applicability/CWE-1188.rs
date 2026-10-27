//@ compiles: safe
// CWE-1188, resource initialised with an insecure default. File::create makes
// the key file with the default mode (0o666 minus umask), typically readable
// by every local user; restricting it needs an explicit OpenOptionsExt::mode.
use std::fs::File;
use std::io::Write;
pub fn save_key(p: &str, key: &[u8]) -> std::io::Result<()> {
    File::create(p)?.write_all(key)
}
