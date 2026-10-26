fn main() {
    let b = Box::new(1u32);
    drop(b);
}
