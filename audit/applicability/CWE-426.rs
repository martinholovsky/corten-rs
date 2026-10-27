//@ compiles: safe
// CWE-426, untrusted search path. Command::new with a bare name resolves the
// program through the inherited PATH, which the invoking user controls.
use std::process::Command;
pub fn sign(file: &str) -> std::io::Result<std::process::Output> {
    Command::new("openssl").args(["dgst", "-sign", "/etc/app/key.pem", file]).output()
}
