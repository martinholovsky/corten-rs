//@ compiles: safe
// CWE-1077, floating point comparison with incorrect operator. f64
// implements PartialEq, so `==` compiles; 0.1 + 0.2 == 0.3 is false and the
// balance check rejects or accepts on rounding error. clippy::float_cmp is
// a lint, not a rustc error.
pub fn fully_paid(paid: f64, due: f64) -> bool {
    paid == due
}
