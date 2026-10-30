//@ compiles: safe
// CWE-20, improper input validation. The quantity is parsed into a signed
// integer and never checked to be positive, so a negative order yields a
// negative total (a refund). Types guarantee it is an i64, not that it is valid.
pub fn order_total(price_cents: i64, qty_input: &str) -> Option<i64> {
    let qty: i64 = qty_input.trim().parse().ok()?;
    price_cents.checked_mul(qty)
}
