//@ compiles: unsafe
// CWE-475, undefined behavior for input to API: from_utf8_unchecked is
// undefined unless the bytes are valid UTF-8; untrusted bytes break that.
pub fn as_text(untrusted: &[u8]) -> &str {
    unsafe { std::str::from_utf8_unchecked(untrusted) }
}
