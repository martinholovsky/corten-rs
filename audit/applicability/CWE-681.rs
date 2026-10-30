//@ compiles: safe
// CWE-681, incorrect numeric conversion. Float-to-int `as` saturates and maps
// NaN to 0, so a negative or NaN amount becomes a charge of 0 cents.
pub fn to_cents(amount: f64) -> u32 {
    (amount * 100.0) as u32
}
