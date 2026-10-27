//@ lint: corten_pub_interior_mut_static
//@ expect: public static of type `std::sync::Mutex<u32>`
//@ expect: public static of type `std::sync::atomic::Atomic<bool>`
//@ count: 2
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
pub static LIMIT: Mutex<u32> = Mutex::new(10);
pub static FLAG: AtomicBool = AtomicBool::new(false);
// Not reported: immutable, or private.
pub static NAME: &str = "corten";
static COUNTER: AtomicBool = AtomicBool::new(false);
fn main() {
    println!("{NAME} {:?} {:?} {:?}", LIMIT.lock().is_ok(), FLAG, COUNTER);
}
