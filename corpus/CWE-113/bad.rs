//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-113: a header value taken from input as a raw string.
use corten_std::http::{HeaderName, HeaderWriter};

pub fn redirect<W: HeaderWriter>(out: &mut W, target: &str) -> bool {
    let Ok(name) = HeaderName::parse("Location") else { return false };
    let value = format!("{target}");
    out.insert(&name, &value).is_ok()
}

fn main() {}
