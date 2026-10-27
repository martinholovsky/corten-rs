//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let e = corten_std::xpath::XQueryExpr(String::from("doc('x')"));
    println!("{e:?}");
}
