//@ good
use corten_std::refine::{Bounded, copy_into};
fn main() {
    let p: Bounded<0, 100> = corten_std::bounded!(0, 100, 42);
    let q = Bounded::<0, 100>::new(7).map_or(0, Bounded::get);
    let mut dst = [0u8; 4];
    let copied = copy_into(&[1, 2], &mut dst).is_ok();
    println!("{} {q} {copied}", p.get());
}
