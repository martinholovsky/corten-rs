//@ compiles: safe
// CWE-256, plaintext storage of a password: the password is written to the
// credential store as-is, with no hashing.
use std::io::Write;
pub fn save_user(path: &str, user: &str, password: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(f, "{user}:{password}")
}
