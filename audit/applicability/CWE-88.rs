//@ compiles: safe
// CWE-88, argument injection. No shell is involved, but a repository URL of
// "--upload-pack=touch /tmp/pwned" is parsed by git as an option, not a
// positional argument, because no "--" separator precedes it.
use std::process::Command;
pub fn clone(repo_url: &str) -> Command {
    let mut c = Command::new("git");
    c.args(["clone", repo_url]);
    c
}
