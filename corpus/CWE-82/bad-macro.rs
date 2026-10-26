//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("<p>{}</p>");
    let _p = corten_std::html!(template, "x");
}
