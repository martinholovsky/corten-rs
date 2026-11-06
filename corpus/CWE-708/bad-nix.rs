//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-708 dependency variant: nix::unistd::chown assigns an owner in safe Rust. The operator's policy does not admit the crate.
fn main() {
    nix::stub();
}
