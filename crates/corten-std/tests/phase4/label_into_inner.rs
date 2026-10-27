//@ expect: no method named `into_inner` found
use corten_std::label::{Labeled, Secret};
fn main() {
    let salary: Labeled<u32, Secret> = Labeled::new(91_000);
    println!("{}", salary.into_inner());
}
