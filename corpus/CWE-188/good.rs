struct Pair {
    a: u16,
    b: u16,
}
fn encode(p: &Pair) -> [u8; 4] {
    let [a0, a1] = p.a.to_le_bytes();
    let [b0, b1] = p.b.to_le_bytes();
    [a0, a1, b0, b1]
}
fn main() {
    println!("{:?}", encode(&Pair { a: 1, b: 2 }));
}
