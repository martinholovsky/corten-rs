//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-708 dependency variant: rustix::fs::fchown assigns an owner in safe Rust. The operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
