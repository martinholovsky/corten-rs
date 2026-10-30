//@ compiles: safe
// CWE-94, code injection. Rust has no eval, but a Rust program can generate
// code for another interpreter: "1); import os; os.system('id'" becomes
// Python statements.
use std::process::Command;
pub fn compute(expr: &str) -> Command {
    let mut c = Command::new("python3");
    c.arg("-c").arg(format!("print({expr})"));
    c
}
