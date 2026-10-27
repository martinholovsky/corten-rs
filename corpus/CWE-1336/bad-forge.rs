//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let m = corten_std::text::TextMessage(String::from("{{7*7}}"));
    println!("{m:?}");
}
