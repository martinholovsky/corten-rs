//@ expect: -F unsafe-code
// CWE-188: relies on the in-memory layout of a repr(Rust) struct.
#[derive(Clone, Copy)]
struct Pair {
    a: u16,
    b: u16,
}
fn main() {
    let p = Pair { a: 1, b: 2 };
    let raw: [u8; 4] = unsafe { std::mem::transmute(p) };
    println!("{raw:?} {} {}", p.a, p.b);
}
