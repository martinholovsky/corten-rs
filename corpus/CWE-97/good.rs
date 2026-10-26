//@ deps: corten-std
fn main() {
    let page = corten_std::html!("<p>{}</p>", "<!--#exec cmd=\"ls\" -->");
    println!("{}", page.as_str());
}
