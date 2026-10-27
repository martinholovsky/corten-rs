//@ compiles: safe
// CWE-767, critical private variable reachable via a public method. The
// balance field is private, but a public setter writes it unchecked.
pub struct Account { balance: i64 }
impl Account {
    pub fn set_balance(&mut self, v: i64) { self.balance = v; }
    pub fn balance(&self) -> i64 { self.balance }
}
