//@ kind: checker
//@ fake-dep: nix
//@ expect: not on the operator's dependency allowlist
// CWE-910 dependency variant: nix::unistd::close takes a bare fd number, so safe code closes a File's
// descriptor and the File then reads whatever reuses it (audit/applicability/crates). Not admitted.
fn main() {
    nix::stub();
}
