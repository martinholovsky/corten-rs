//@ expect: associated function `new` is private
use corten_std::label::DeclassifyCap;
fn main() {
    let cap = DeclassifyCap::new("anything".to_owned());
    println!("{}", cap.name());
}
