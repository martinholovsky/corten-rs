//@ rejected: cannot move out of `*self`
// CWE-1082: safe code cannot destroy an instance through a borrow of it; a
// method can only take `self` by value, which ends the caller's use.
pub struct Node {
    pub data: Vec<u8>,
}
impl Node {
    pub fn destroy(&self) {
        drop(*self);
    }
}
