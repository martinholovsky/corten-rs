//@ kind: language
//@ deps: corten-std
//@ expect: is private
// A PathSeg cannot be built without its parser.
fn main() {
    let seg = corten_std::path::PathSeg(String::from("../etc"));
    println!("{seg}");
}
