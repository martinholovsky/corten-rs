use std::sync::Mutex;
fn main() {
    let m = Mutex::new(0u32);
    match m.lock() {
        Ok(mut g) => *g = 1,
        Err(e) => println!("{e}"),
    }
    println!("{:?}", m.lock().map(|g| *g));
}
