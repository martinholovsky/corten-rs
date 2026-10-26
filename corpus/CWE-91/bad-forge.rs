//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let e = corten_std::xpath::XPathExpr(String::from("//*"));
    println!("{e:?}");
}
