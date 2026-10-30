//@ rejected: non-exhaustive patterns
// CWE-478 variant: the switch-style spelling. rustc rejects a `match` that
// does not cover every value, so a C-style switch with no default and no
// matching arm cannot be written with `match`.
pub fn level(code: u8) -> &'static str {
    match code {
        0 => "guest",
        1 => "user",
    }
}
