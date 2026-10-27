//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let page = corten_std::html::Html(String::from("<script>alert(1)</script>"));
    println!("{page:?}");
}
