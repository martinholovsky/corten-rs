//@ compiles: safe
// CWE-208, observable timing discrepancy. Slice == returns at the first
// differing byte, so response time reveals how much of the token matched.
pub fn check_token(given: &[u8], expected: &[u8]) -> bool {
    given == expected
}
