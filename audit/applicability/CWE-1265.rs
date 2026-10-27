//@ compiles: safe
// CWE-1265, unintended reentrant invocation: withdraw calls out before updating
// the balance; with Cell-based state the callback can re-enter withdraw and
// pay twice (the borrow checker stops this for &mut, not for interior mutability).
use std::cell::Cell;
pub struct Account { pub balance: Cell<u64> }
impl Account {
    pub fn withdraw(&self, amount: u64, send: &dyn Fn(&Account, u64)) {
        if self.balance.get() >= amount {
            send(self, amount);
            self.balance.set(self.balance.get().saturating_sub(amount));
        }
    }
}
