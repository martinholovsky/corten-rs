//@ expect: E0507
// CWE-1082: an object that destroys itself through a borrowed self.
struct Res(Vec<u8>);
impl Res {
    fn destroy(&self) {
        drop(*self);
    }
}
fn main() {
    let r = Res(vec![1]);
    r.destroy();
}
