//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-403 dependency variant: rustix::io::fcntl_setfd clears close-on-exec in safe Rust, so a child
// inherits the descriptor (audit/applicability/crates). The operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
