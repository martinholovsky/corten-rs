//@ expect: expected
//@ absent
// CWE-1055: multiple inheritance from concrete classes.
struct A;
struct B;
struct C: A, B;
fn main() {}
