//@ compiles: safe
// CWE-385, covert timing channel. Slice equality stops at the first
// differing byte, so response time reveals how much of the token matched.
pub fn token_ok(given: &[u8], expected: &[u8]) -> bool {
    given == expected
}
