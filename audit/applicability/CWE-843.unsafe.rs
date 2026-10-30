//@ compiles: unsafe
// CWE-843 in unsafe Rust: a Value written as an integer is read as a &str,
// so the integer is used as a pointer and length.
pub union Value {
    pub n: usize,
    pub s: &'static str,
}
pub fn as_text(v: &Value) -> &'static str {
    unsafe { v.s }
}
