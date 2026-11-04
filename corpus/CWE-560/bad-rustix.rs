//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-560 dependency variant: rustix::process::umask takes a chmod-style value in safe Rust
// (audit/applicability/crates). The operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
