//@ rejected: E0133
// CWE-587 attempted in safe Rust: casting a constant to a raw pointer compiles,
// but reading through it requires unsafe, so the fixed address is never used.
pub fn read_status() -> u32 {
    let p = 0x4000_1000usize as *const u32;
    p.read_volatile()
}
