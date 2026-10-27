//@ compiles: safe
// CWE-783, operator precedence: `-` binds tighter than `<<`, so this is
// 1 << (bits - 1), not (1 << bits) - 1.
pub fn low_mask(bits: u32) -> u32 {
    1 << bits - 1
}
