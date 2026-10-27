//@ compiles: unsafe
// CWE-468, incorrect pointer scaling: `add` already scales by size_of::<u32>(),
// so multiplying the offset by 4 again skips four times too far.
pub fn nth(words: &[u32], n: usize) -> u32 {
    unsafe { *words.as_ptr().add(n * std::mem::size_of::<u32>()) }
}
