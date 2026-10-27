//@ good
use corten_std::label::{Internal, Labeled, Public, Secret};
fn main() {
    let a: Labeled<u32, Internal> = Labeled::new(2);
    let b: Labeled<u32, Secret> = Labeled::new(3);
    let _sum: Labeled<u32, Secret> = a.join(b, u32::saturating_add);
    let raised: Labeled<u32, Secret> = Labeled::<u32, Internal>::new(1).relabel();
    let _ = raised;
    let shown: Labeled<u32, Public> = Labeled::new(5);
    let page = corten_std::html!("<p>{}</p>", shown.into_inner());
    println!("{}", page.as_str());
}
