fn main() {
    let b = Box::new(5u32);
    let v = *b;
    drop(b);
    println!("{v}");
}
