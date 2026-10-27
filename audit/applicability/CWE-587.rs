//@ compiles: unsafe
// CWE-587, fixed address assigned to a pointer, then dereferenced.
pub fn read_status() -> u32 {
    let p = 0x4000_1000usize as *const u32;
    unsafe { p.read_volatile() }
}
