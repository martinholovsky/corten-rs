//@ compiles: safe
// CWE-841, behavioral workflow not enforced: shipping only checks that a cart
// exists, not that the payment step completed.
pub enum State { Cart, Paid, Shipped }
pub fn ship(s: &mut State) {
    *s = State::Shipped;
}
