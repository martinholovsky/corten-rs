//@ rejected: dereference of raw pointer is unsafe
// CWE-476: dereferencing a possibly-null raw pointer outside unsafe is refused.
pub fn read(p: *const i32) -> i32 {
    *p
}
