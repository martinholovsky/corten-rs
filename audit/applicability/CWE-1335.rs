//@ compiles: safe
// CWE-1335, incorrect bitwise shift: the shift amount comes from input; with
// overflow-checks off, a shift >= 32 is masked to its low five bits, giving a
// wrong value instead of zero.
pub fn flag(bit: u32) -> u32 {
    1u32 << bit
}
