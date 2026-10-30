//@ compiles: safe
// CWE-573, caller not following the spec: std says it is a logic error to
// change a key's hash while it is in a HashSet; Cell lets safe code do it.
use std::cell::Cell;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
#[derive(PartialEq, Eq)]
pub struct Key(pub Cell<u32>);
impl Hash for Key {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.0.get().hash(h)
    }
}
pub fn bump(set: &HashSet<Key>) {
    for k in set {
        k.0.set(k.0.get() + 1);
    }
}
