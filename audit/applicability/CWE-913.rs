//@ compiles: safe
// CWE-913, improper control of dynamically-managed code resources. An object
// whose attributes live in a map lets the request write any attribute,
// including the "role" the authorisation code reads.
use std::collections::HashMap;
pub struct DynObject {
    pub attrs: HashMap<String, String>,
}
pub fn apply(o: &mut DynObject, request: &[(String, String)]) {
    for (k, v) in request {
        o.attrs.insert(k.clone(), v.clone());
    }
}
