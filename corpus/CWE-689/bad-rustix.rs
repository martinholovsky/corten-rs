//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-689 dependency variant: rustix::fs::chmod after the copy is written. The operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
