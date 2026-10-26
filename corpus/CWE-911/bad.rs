//@ expect: -F unsafe-code
// CWE-911: decrements a reference count it never incremented.
use std::rc::Rc;
fn main() {
    let a = Rc::new(5u32);
    let p = Rc::as_ptr(&a);
    unsafe { Rc::decrement_strong_count(p) };
    println!("{a}");
}
