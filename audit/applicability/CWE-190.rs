//@ compiles: safe
// CWE-190, integer overflow: qty * unit_cents wraps silently in release builds
// (overflow-checks off by default), producing a tiny total.
pub fn total_cents(qty: u32, unit_cents: u32) -> u32 {
    qty * unit_cents
}
