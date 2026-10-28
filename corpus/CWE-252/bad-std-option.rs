//@ expect: corten-must-use-return
// CWE-252 bypass-hunt variant (2026-10-27): the `Option` that
// `HashMap::remove` returns is the only sign the token existed. Ignoring it
// reports a revocation that did nothing. The must-use rule covers local
// functions and `bool` from any crate, not another crate's `Option`.
use std::collections::HashMap;
fn main() {
    let mut sessions: HashMap<&str, u32> = HashMap::new();
    sessions.insert("live", 1);
    sessions.remove("unknown-token");
    println!("revoked");
}
