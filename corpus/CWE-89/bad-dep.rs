//@ kind: checker
//@ fake-dep: my-raw-sql
//@ expect: not on the operator's dependency allowlist
// CWE-89 dependency variant (2026-10-27): a database crate whose API takes
// SQL as a string (`client.query(&format!(...))`). The typed sink governs
// the prelude, not what a dependency offers; the stub stands in for the
// crate. Refused: the operator's policy does not admit the crate (docs/gates/phase-5.md).
fn main() {
    my_raw_sql::stub();
}
