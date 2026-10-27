//@ rejected: explicit use of destructor method
// CWE-583, public finalize(). Rust has no finalizers; its destructor
// Drop::drop cannot be called directly, only run once by the compiler.
pub struct Conn;
impl Drop for Conn {
    fn drop(&mut self) {}
}
pub fn attacker(c: &mut Conn) {
    c.drop();
}
