//@ compiles: safe
// CWE-674, uncontrolled recursion: nesting depth comes from the input, and the
// recursion has no limit, so deep input overflows the stack (abort).
pub fn depth(s: &[u8]) -> usize {
    match s.first() {
        Some(b'[') => 1 + depth(&s[1..]),
        _ => 0,
    }
}
