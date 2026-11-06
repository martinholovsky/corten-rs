//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-276 dependency variant: nix::sys::stat::fchmod sets any mode in safe Rust. The operator's policy does not admit the crate.
fn main() {
    nix::stub();
}
