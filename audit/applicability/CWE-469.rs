//@ compiles: safe
// CWE-469, pointer subtraction to determine size: the pointers belong to
// different allocations, so the difference is meaningless; the slice then
// panics or covers the wrong bytes.
pub fn span<'a>(start: &'a [u8], end: &[u8]) -> &'a [u8] {
    let len = (end.as_ptr() as usize).wrapping_sub(start.as_ptr() as usize);
    &start[..len]
}
