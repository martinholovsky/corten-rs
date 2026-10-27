//@ compiles: safe
// CWE-214, process invoked with visible sensitive information. The password
// is passed on the child's command line, readable by any local user via ps.
use std::process::Command;
pub fn dump(password: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("mysqldump").arg(format!("--password={password}")).arg("prod").status()
}
