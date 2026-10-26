//@ expect: -F clippy::mem-forget
// CWE-1091: discards an object without running its destructor.
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        println!("released");
    }
}
fn main() {
    let g = Guard;
    std::mem::forget(g);
}
