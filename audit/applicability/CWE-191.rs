//@ compiles: safe
// CWE-191, integer underflow: balance - amount wraps to a huge u64 in release
// builds when amount exceeds balance.
pub fn withdraw(balance: u64, amount: u64) -> u64 {
    balance - amount
}
