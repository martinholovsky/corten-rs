//@ expect: E0449
// CWE-583: a finalizer declared public.
struct Res;
impl Drop for Res {
    pub fn drop(&mut self) {}
}
fn main() {
    let _r = Res;
}
