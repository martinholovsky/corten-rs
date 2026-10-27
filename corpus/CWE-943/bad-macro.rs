//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("SELECT {}");
    let _q = corten_std::sql!(template, 1);
}
