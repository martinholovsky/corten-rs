//@ deps: corten-std
use corten_std::http::{HeaderName, HeaderValue, HeaderWriter};

pub fn redirect<W: HeaderWriter>(out: &mut W, target: &str) -> Result<bool, String> {
    let name = HeaderName::parse("Location").map_err(|e| e.to_string())?;
    let value = HeaderValue::parse(target).map_err(|e| e.to_string())?;
    Ok(out.insert(&name, &value).is_ok())
}

fn main() {}
