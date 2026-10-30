//@ compiles: safe
// CWE-1025, comparison using wrong factors. The session check compares
// lengths of the tokens instead of their contents, so any token of the
// right length is accepted. Both sides are usize; the types are fine.
pub fn session_valid(expected: &str, presented: &str) -> bool {
    expected.len() == presented.len()
}
