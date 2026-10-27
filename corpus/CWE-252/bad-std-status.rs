//@ expect: corten-must-use-return
// CWE-252 bypass-hunt variant: a status from a standard-library function is
// ignored. `HashSet::insert` returns false for a repeat, so a replay goes
// unnoticed. The must-use rule covers functions in the checked crate only
// (owner decision 10), so this passes the checker. Not detected.
use std::collections::HashSet;
fn main() {
    let mut seen = HashSet::new();
    for id in [7u32, 7] {
        seen.insert(id);
        println!("accepted {id}");
    }
}
