//@ deps: corten-std
use corten_std::xpath::XQueryEvaluator;

pub fn find<X: XQueryEvaluator>(engine: &mut X, name: &str) -> Result<Vec<String>, X::Error> {
    engine.evaluate(&corten_std::xquery!("doc('users.xml')//user[name = {}]", name))
}

fn main() {}
