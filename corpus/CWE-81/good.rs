//@ deps: corten-std
use corten_std::html::HtmlWriter;

pub fn greet<W: HtmlWriter>(out: &mut W, name: &str) -> Result<(), W::Error> {
    out.write_html(&corten_std::html!("<p class=\"greeting\">Hello, {}</p>", name))
}

fn main() {}
