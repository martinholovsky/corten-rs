//@ rejected: explicit use of destructor method
// CWE-568, finalize() without super.finalize(). Rust has no finalizers and no
// inheritance; drop glue always drops every field after Drop::drop, and a
// manual "super" drop call is refused (E0040).
pub struct Base;
impl Drop for Base {
    fn drop(&mut self) {}
}
pub struct Derived {
    pub base: Base,
}
impl Drop for Derived {
    fn drop(&mut self) {
        self.base.drop();
    }
}
