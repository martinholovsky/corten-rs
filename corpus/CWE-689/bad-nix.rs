//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-689 dependency variant: nix::sys::stat::fchmod after the copy is written. The operator's policy does not admit the crate.
fn main() {
    nix::stub();
}
