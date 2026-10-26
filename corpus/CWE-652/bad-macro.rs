//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("{}");
    let _e = corten_std::xquery!(template, "x");
}
