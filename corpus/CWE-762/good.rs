fn main() {
    let b = Box::new(1u8);
    drop(b);
}
