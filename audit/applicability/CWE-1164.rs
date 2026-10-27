//@ compiles: safe
// CWE-1164, irrelevant code: the first statement computes a value and
// discards it; removing it changes nothing.
pub fn size(v: &[u8]) -> usize {
    let _ = v.iter().map(|b| *b as usize).sum::<usize>();
    v.len()
}
