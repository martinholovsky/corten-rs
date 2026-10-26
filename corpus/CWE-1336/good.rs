//@ deps: corten-std
use corten_std::text::TextSender;

pub fn welcome<T: TextSender>(mail: &mut T, name: &str) -> Result<(), T::Error> {
    mail.send(&corten_std::text!("Hello {}, welcome.", name))
}

fn main() {}
