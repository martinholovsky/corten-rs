//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-652: an XQuery expression built by string formatting.
use corten_std::xpath::XQueryEvaluator;

pub fn find<X: XQueryEvaluator>(engine: &mut X, name: &str) -> bool {
    let expr = format!("doc('users.xml')//user[name = \"{name}\"]");
    engine.evaluate(&expr).is_ok()
}

fn main() {}
