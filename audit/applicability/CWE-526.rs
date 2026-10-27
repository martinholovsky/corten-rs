//@ compiles: safe
// CWE-526, cleartext sensitive data in an environment variable. The secret
// is placed in the child's environment (inherited by its children, visible
// in /proc/<pid>/environ). std::env::set_var is unsafe in edition 2024, but
// Command::env is safe.
use std::process::Command;
pub fn run_job(db_password: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("job").env("DB_PASSWORD", db_password).status()
}
