//@ compiles: safe
// CWE-114, process control. The helper binary to execute is taken from an
// attacker-influenced environment variable and run with our privileges.
use std::process::Command;
pub fn run_helper() -> std::io::Result<std::process::ExitStatus> {
    let helper = std::env::var("APP_HELPER").unwrap_or_else(|_| "helper".into());
    Command::new(helper).status()
}
