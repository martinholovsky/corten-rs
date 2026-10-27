//@ expect: expected expression, found `$`
//@ absent
// CWE-914: writes a variable selected by external input.
fn main() {
    let key = String::from("is_admin");
    ${key} = true;
}
