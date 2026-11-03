//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-403 dependency variant: nix::fcntl::fcntl(F_SETFD) clears close-on-exec in safe Rust, so a
// child inherits the descriptor (audit/applicability/crates). The operator's policy does not admit the crate.
fn main() {
    nix::stub();
}
