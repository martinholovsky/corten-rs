//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-643: an XPath expression built by string formatting.
use corten_std::xpath::XPathEvaluator;

pub fn find<X: XPathEvaluator>(engine: &mut X, name: &str) -> bool {
    let expr = format!("//user[name='{name}']/@id");
    engine.evaluate(&expr).is_ok()
}

fn main() {}
