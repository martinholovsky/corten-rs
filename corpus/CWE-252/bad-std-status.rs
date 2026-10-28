//@ expect: corten-must-use-return
// CWE-252 bypass-hunt variant: a status from a standard-library function is
// ignored. `HashSet::insert` returns false for a repeat, so a replay goes
// unnoticed. Passed the narrowed rule (owner decision 10); detected since
// the rule covers `bool` from any crate (2026-10-27).
use std::collections::HashSet;
fn main() {
    let mut seen = HashSet::new();
    for id in [7u32, 7] {
        seen.insert(id);
        println!("accepted {id}");
    }
}
