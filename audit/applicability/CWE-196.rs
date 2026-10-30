//@ compiles: safe
// CWE-196, unsigned to signed conversion error. A large u32 becomes negative
// through `as i32`, so the upper-bound check passes for 0x8000_0000.
pub fn offset_ok(n: u32) -> bool {
    let off = n as i32;
    off < 1024
}
