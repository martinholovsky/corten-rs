//@ expect: closures can only be coerced to `fn` types if they do not capture any variables
use corten_std::label::{Labeled, Secret};
fn main() {
    let mut stash = String::new();
    let token: Labeled<String, Secret> = Labeled::new("s3cr3t".to_owned());
    let _same = token.map(|t| {
        stash.push_str(&t);
        t
    });
    println!("{stash}");
}
