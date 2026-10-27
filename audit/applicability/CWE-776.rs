//@ compiles: safe
// CWE-776, recursive entity expansion (billion laughs). Entities expand
// recursively with no depth or output-size limit.
use std::collections::HashMap;
pub fn expand(name: &str, ents: &HashMap<String, Vec<String>>) -> String {
    match ents.get(name) {
        Some(parts) => parts.iter().map(|p| expand(p, ents)).collect(),
        None => name.to_string(),
    }
}
