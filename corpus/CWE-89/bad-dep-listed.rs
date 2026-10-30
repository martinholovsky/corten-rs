//@ kind: checker
//@ fake-dep: my-raw-sql
//@ dep-policy: allow my-raw-sql
//@ dep-policy: ban my_raw_sql::stub raw SQL string; use the prelude's sql! and SqlExecutor
//@ expect: operator dependency policy: raw SQL string
// CWE-89 dependency variant: the operator admits a database crate but bans
// its entry point that takes SQL as a string (the stub stands in for it).
// Local code that calls it is refused (docs/gates/phase-5.md).
fn main() {
    my_raw_sql::stub();
}
