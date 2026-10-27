//@ compiles: safe
// CWE-570, expression always false: an unsigned value is never negative,
// so the bounds check never fires; rustc only warns (unused_comparisons).
pub fn reject(offset: u32) -> bool {
    offset < 0
}
