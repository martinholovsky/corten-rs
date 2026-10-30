//@ compiles: unsafe
// CWE-586, explicit call to the finalizer: drop_in_place runs Conn's
// destructor explicitly, and it runs again when `c` leaves scope.
pub struct Conn {
    pub fd: i32,
}
impl Drop for Conn {
    fn drop(&mut self) {
        self.fd = -1;
    }
}
pub fn finish(mut c: Conn) {
    unsafe {
        std::ptr::drop_in_place(&mut c);
    }
}
