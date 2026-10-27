//@ expect: Eq
// CWE-581: a hash key with a hash function but no equality.
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
struct Key(u32);
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
fn main() {
    let mut m = HashMap::new();
    m.insert(Key(1), "one");
}
