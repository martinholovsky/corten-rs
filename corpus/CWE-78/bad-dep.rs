//@ fake-dep: my-shell
//@ expect: not on the operator's dependency allowlist
// CWE-78 dependency variant (2026-10-27): a crate that runs a shell command
// line built from a string. The checker bans `std::process::Command` in the
// checked crate, not inside a dependency; the stub stands in for the crate.
// Refused: the operator's policy does not admit the crate (docs/gates/phase-5.md).
fn main() {
    my_shell::stub();
}
