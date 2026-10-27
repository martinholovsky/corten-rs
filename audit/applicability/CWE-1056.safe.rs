//@ rejected: `...` is not supported for non-extern functions
// CWE-1056: a variadic Rust function definition is refused.
pub fn sum(_n: usize, _args: ...) -> i32 {
    0
}
