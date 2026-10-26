//@ expect: expected
//@ absent
// CWE-397: declares that a function throws a generic exception.
fn load() throws Exception {}
fn main() {}
