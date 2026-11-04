//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-1341 dependency variant: nix::unistd::close takes a bare fd number, so safe code closes one
// descriptor twice (audit/applicability/crates). The operator's policy does not admit the crate.
fn main() {
    nix::stub();
}
