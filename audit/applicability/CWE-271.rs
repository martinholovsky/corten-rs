//@ compiles: safe
// CWE-271, privilege dropping errors: a process running as root launches a
// user-chosen command without setting the child's uid (CommandExt::uid), so
// the child inherits root.
use std::process::{Child, Command};
pub fn run_user_hook(user_command: &str) -> std::io::Result<Child> {
    Command::new(user_command).spawn()
}
