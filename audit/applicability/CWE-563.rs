//@ compiles: safe
// CWE-563, assignment without use: the validation result is overwritten.
fn validate(s: &str) -> bool {
    !s.contains('/')
}
pub fn check(input: &str) -> bool {
    let mut ok = validate(input);
    ok = true;
    ok
}
