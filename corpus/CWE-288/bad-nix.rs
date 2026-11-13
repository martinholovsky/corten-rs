//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-288 dependency variant: the same through nix.
fn main() {
    nix::stub();
}
