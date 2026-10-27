//@ expect: -F unused-must-use
// CWE-252: ignores a status returned as bool. Needs the must-use-on-every-
// non-unit-return lint (not implemented), so this variant is expected to
// pass the checker today.
fn store(v: u32) -> bool {
    v <= 10
}
fn main() {
    store(30);
}
