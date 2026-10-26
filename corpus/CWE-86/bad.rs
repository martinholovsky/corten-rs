//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-86: markup built by string formatting and sent as HTML.
use corten_std::html::HtmlWriter;

pub fn greet<W: HtmlWriter>(out: &mut W, name: &str) -> bool {
    let page = format!("<p>Hello, {name}</p>");
    out.write_html(&page).is_ok()
}

fn main() {}
