//@ deps: corten-std
// Matched benign program: a granted program, argv, operands after --.
use corten_std::process::{ArgError, ExecCap, ProcessInvocation};

pub fn archive(tar: &ExecCap, name: &str) -> Result<ProcessInvocation, ArgError> {
    corten_std::process!(*tar, "-c", "-f"; name)
}

fn main() {
    let f: fn(&ExecCap, &str) -> Result<ProcessInvocation, ArgError> = archive;
    let _keep = f;
}
