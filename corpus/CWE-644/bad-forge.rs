//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let v = corten_std::http::HeaderValue(String::from("x\r\nSet-Cookie: a=b"));
    println!("{v:?}");
}
