//@ rejected: access to union field is unsafe
// CWE-843, type confusion. Reading a union through a different field than was
// written is the Rust spelling; safe Rust refuses union field reads (E0133).
pub union Value {
    pub n: usize,
    pub s: &'static str,
}
pub fn as_text(v: &Value) -> &'static str {
    v.s
}
