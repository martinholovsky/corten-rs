//@ expect: expected expression, found `$`
//@ absent
// CWE-624: a regular expression whose replacement is executed as code.
fn main() {
    let s = preg_replace("/x/e", $code, "x");
}
