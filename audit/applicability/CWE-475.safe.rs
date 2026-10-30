//@ rejected: requires unsafe
// CWE-475: the precondition-carrying API cannot be called from safe code;
// safe std APIs (str::from_utf8) check their input instead.
pub fn as_text(untrusted: &[u8]) -> &str {
    std::str::from_utf8_unchecked(untrusted)
}
