//@ compiles: safe
// CWE-369, divide by zero: count comes from input; integer division by zero
// panics (DoS), and float division would yield inf/NaN.
pub fn average(total: u64, count: u64) -> u64 {
    total / count
}
