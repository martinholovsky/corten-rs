//@ rejected: expected `{`
// CWE-483, incorrect block delimitation. Rust's grammar requires braces around
// every if/else/loop body, so the brace-less C form does not parse.
pub fn check(ok: bool) -> u32 {
    if !ok
        log_failure();
        return 1;
    0
}
fn log_failure() {}
