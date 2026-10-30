//@ compiles: safe
// CWE-758, reliance on unspecified behavior: HashMap iteration order is
// unspecified (and randomized per process); "first" user varies run to run.
use std::collections::HashMap;
pub fn first_user(m: &HashMap<String, u32>) -> Option<&String> {
    m.keys().next()
}
