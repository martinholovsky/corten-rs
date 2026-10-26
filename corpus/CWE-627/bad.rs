//@ expect: expected expression, found `$`
//@ absent
// CWE-627: a variable whose name is chosen at run time.
fn main() {
    let name = "admin";
    $$name = true;
}
