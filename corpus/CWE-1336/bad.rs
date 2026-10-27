//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-1336: a message template assembled from input.
use corten_std::text::TextSender;

pub fn welcome<T: TextSender>(mail: &mut T, template: &str, name: &str) -> bool {
    let message = template.replace("{name}", name);
    mail.send(&message).is_ok()
}

fn main() {}
