//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("Hello {}");
    let _m = corten_std::text!(template, "x");
}
