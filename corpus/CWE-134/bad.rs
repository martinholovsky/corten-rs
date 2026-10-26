//@ expect: format argument must be a string literal
// CWE-134: uses externally controlled text as the format string.
fn main() {
    let user = String::from("{}{}");
    println!(user, 1);
}
