//@ compiles: safe
// CWE-837, single unique action not enforced: the coupon is applied but never
// marked as used, so it can be redeemed repeatedly.
pub struct Coupon { pub value: u64, pub used: bool }
pub fn redeem(c: &Coupon, total: &mut u64) {
    *total = total.saturating_sub(c.value);
}
