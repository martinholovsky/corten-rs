//@ compiles: safe
// CWE-1061, insufficient encapsulation: the index must match entries, but
// both are public, so any caller can break the invariant.
use std::collections::HashMap;
pub struct Cache {
    pub entries: Vec<String>,
    pub index: HashMap<String, usize>,
}
