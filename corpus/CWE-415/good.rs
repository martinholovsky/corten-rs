fn main() {
    let b = Box::new(5u32);
    drop(b);
}
