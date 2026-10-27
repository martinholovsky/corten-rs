//@ compiles: safe
// CWE-427, uncontrolled search path element. The child's PATH puts the
// current (attacker-writable) directory first.
use std::process::Command;
pub fn compress(path: &str) -> std::io::Result<std::process::ExitStatus> {
    let old = std::env::var("PATH").unwrap_or_default();
    Command::new("gzip").env("PATH", format!(".:{old}")).arg(path).status()
}
