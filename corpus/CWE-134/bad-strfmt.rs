//@ kind: checker
//@ fake-dep: strfmt
//@ expect: not on the operator's dependency allowlist
// CWE-134 dependency variant: strfmt formats with a runtime format string, so external text chooses
// which values are printed (audit/applicability/crates). The operator's policy does not admit the crate.
fn main() {
    strfmt::stub();
}
