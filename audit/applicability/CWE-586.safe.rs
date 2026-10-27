//@ rejected: explicit use of destructor method
// CWE-586: calling Drop::drop directly is refused (E0040); safe code can
// only drop(c), which consumes the value so the destructor runs once.
pub struct Conn {
    pub fd: i32,
}
impl Drop for Conn {
    fn drop(&mut self) {
        self.fd = -1;
    }
}
pub fn finish(mut c: Conn) {
    c.drop();
}
