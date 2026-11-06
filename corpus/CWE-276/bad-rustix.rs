//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-276 dependency variant: rustix::fs::chmod sets any mode in safe Rust. The operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
