//@ compiles: safe
// CWE-471, modification of assumed-immutable data. The price round-trips
// through a hidden form field and is trusted on return; the client can edit
// it. Rust's & immutability covers memory, not data outside the process.
pub struct OrderForm {
    pub item: String,
    pub price_cents: u64,
}
pub fn amount_to_charge(f: &OrderForm) -> u64 {
    f.price_cents
}
