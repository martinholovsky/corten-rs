//@ compiles: safe
// CWE-1090, method accessing another type's member: Order reads Customer's
// field directly instead of through Customer's methods.
pub struct Customer {
    pub credit_limit: u64,
}
pub struct Order {
    pub total: u64,
}
impl Order {
    pub fn approved(&self, c: &Customer) -> bool {
        self.total <= c.credit_limit
    }
}
