//@ lint: corten_must_use_return
//@ expect: the `bool` this call returns is discarded
//@ expect: the `std::option::Option<u32>` this call returns is discarded
//@ expect: the `i32` this call returns is discarded
//@ count: 5
use std::collections::{BTreeMap, BTreeSet};
fn ok() -> bool {
    true
}
fn lookup() -> Option<u32> {
    None
}
fn status() -> i32 {
    -1
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
    lookup();
    status();
    // Reported: a `bool` status from another crate.
    let mut seen = BTreeSet::new();
    seen.insert(7u32);
    // Not reported: a `bool` bound to a name, a non-`bool` from another
    // crate (owner decision 10), a builder returning its own receiver, a
    // used value.
    let _was_new = seen.insert(8);
    let mut m = BTreeMap::new();
    m.insert(1, 2u32);
    let mut b = Builder(0);
    b.add(1).add(2);
    println!("{}", b.0);
    if ok() {
        drop(m);
    }
}
