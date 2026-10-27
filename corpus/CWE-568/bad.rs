//@ expect: E0040
// CWE-568: a finalizer that does not run its parent's cleanup. Rust runs
// field destructors itself; calling one by hand is rejected.
struct Inner;
impl Drop for Inner {
    fn drop(&mut self) {}
}
struct Outer {
    inner: Inner,
}
impl Drop for Outer {
    fn drop(&mut self) {
        self.inner.drop();
    }
}
fn main() {
    let _o = Outer { inner: Inner };
}
