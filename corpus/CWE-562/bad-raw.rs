//@ kind: checker
//@ expect: -F unsafe-code
// CWE-562 through a raw pointer, which the borrow checker does not track.
fn make() -> *const u32 {
    let x = 5;
    &raw const x
}
fn main() {
    let v = unsafe { *make() };
    println!("{v}");
}
