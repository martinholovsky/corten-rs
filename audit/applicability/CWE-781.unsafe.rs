//@ compiles: unsafe
// CWE-781, METHOD_NEITHER IOCTL address not validated. The handler reads the
// caller-supplied address with no ProbeForRead-style check, so a user can
// point it at kernel memory.
pub fn ioctl_read(user_addr: usize, len: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(user_addr as *const u8, len).to_vec() }
}
