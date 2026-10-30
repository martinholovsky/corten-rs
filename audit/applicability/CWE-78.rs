//@ compiles: safe
// CWE-78, OS command injection. The host name is spliced into a shell
// command line; "x; rm -rf ~" runs a second command. std::process::Command
// does not invoke a shell, but nothing stops the program from asking for one.
use std::process::Command;
pub fn ping(host: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(format!("ping -c 1 {host}"));
    c
}
