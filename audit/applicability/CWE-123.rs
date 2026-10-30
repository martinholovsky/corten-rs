//@ compiles: unsafe
// CWE-123, write-what-where: attacker-chosen value written to an
// attacker-chosen address.
pub fn write_what_where(addr: usize, value: usize) {
    unsafe { *(addr as *mut usize) = value };
}
