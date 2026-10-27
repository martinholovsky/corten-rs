//@ kind: language
//@ expect: cannot be sent between threads safely
// Sharing a non-thread-safe value across threads does not compile.
use std::rc::Rc;
fn main() {
    let shared = Rc::new(5u32);
    let copy = Rc::clone(&shared);
    let handle = std::thread::spawn(move || *copy);
    println!("{:?}", handle.join());
}
