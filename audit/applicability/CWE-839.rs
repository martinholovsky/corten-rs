//@ compiles: safe
// CWE-839, numeric range comparison without minimum check. The amount is
// checked against the maximum only; a negative amount passes and
// increases the balance. No overflow or bounds check is involved, so safe
// Rust compiles and runs it.
pub fn withdraw(balance: &mut i64, amount: i64) -> bool {
    const MAX_WITHDRAWAL: i64 = 1_000;
    if amount <= MAX_WITHDRAWAL {
        *balance -= amount;
        true
    } else {
        false
    }
}
