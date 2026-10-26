//@ expect: E0040
// CWE-586: calls a finalizer explicitly.
struct Res;
impl Drop for Res {
    fn drop(&mut self) {}
}
fn main() {
    let mut r = Res;
    r.drop();
}
