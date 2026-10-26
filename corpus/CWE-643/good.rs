//@ deps: corten-std
use corten_std::xpath::XPathEvaluator;

pub fn find<X: XPathEvaluator>(engine: &mut X, name: &str) -> Result<Vec<String>, X::Error> {
    engine.evaluate(&corten_std::xpath!("//user[name={}]/@id", name))
}

fn main() {}
