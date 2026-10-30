//@ compiles: safe
// CWE-682, incorrect calculation: dividing before multiplying truncates, so a
// 99-cent item gets a zero discount at any percentage.
pub fn discount_cents(price_cents: u64, pct: u64) -> u64 {
    price_cents / 100 * pct
}
