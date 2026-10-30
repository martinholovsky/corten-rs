//@ rejected: binary operation `==` cannot be applied
// CWE-1097: a type without PartialEq has no fallback identity comparison
// (unlike Java's Object.equals); comparing it does not compile.
pub struct Record {
    pub id: u64,
}
pub fn same(a: &Record, b: &Record) -> bool {
    *a == *b
}
