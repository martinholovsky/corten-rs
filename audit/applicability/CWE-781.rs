//@ rejected: dereference of raw pointer is unsafe
// CWE-781, METHOD_NEITHER IOCTL address not validated. The user-mode buffer
// arrives as a bare address; reading it means dereferencing a raw pointer,
// which safe Rust refuses.
pub fn ioctl_read(user_addr: usize) -> u8 {
    *(user_addr as *const u8)
}
