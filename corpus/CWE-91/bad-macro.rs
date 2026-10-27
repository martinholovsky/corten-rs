//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("//user[name={}]");
    let _e = corten_std::xpath!(template, "x");
}
