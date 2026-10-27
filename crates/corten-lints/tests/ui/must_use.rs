//@ lint: corten_must_use_return
//@ expect: the `bool` this call returns is discarded
//@ expect: the `std::option::Option<u32>` this call returns is discarded
//@ count: 3
use std::collections::BTreeMap;
fn ok() -> bool {
    true
}
struct Builder(u32);
impl Builder {
    fn add(&mut self, n: u32) -> &mut Self {
        self.0 = self.0.saturating_add(n);
        self
    }
}
fn main() {
    ok();
    let _ = ok();
    let mut m = BTreeMap::new();
    m.insert(1, 2u32);
    // Not reported: a builder returning its own receiver, a unit call, a used value.
    let mut b = Builder(0);
    b.add(1).add(2);
    println!("{}", b.0);
    if ok() {
        drop(m);
    }
}
