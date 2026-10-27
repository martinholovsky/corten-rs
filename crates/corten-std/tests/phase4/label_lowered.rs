//@ expect: expected `Labeled<&str, Public>`, found `Labeled<&str, Secret>`
use corten_std::label::{Labeled, Public, Secret};
fn main() {
    let token: Labeled<&str, Secret> = Labeled::new("s3cr3t");
    let open: Labeled<&str, Public> = token.relabel();
    println!("{}", open.into_inner());
}
