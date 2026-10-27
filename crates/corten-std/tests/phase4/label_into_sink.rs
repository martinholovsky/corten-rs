//@ expect: the trait bound `HtmlArg: From<Labeled<&str, corten_std::label::Secret>>` is not satisfied
use corten_std::label::{Labeled, Secret};
fn main() {
    let token: Labeled<&str, Secret> = Labeled::new("s3cr3t");
    let page = corten_std::html!("<p>{}</p>", token);
    println!("{}", page.as_str());
}
