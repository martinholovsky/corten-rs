fn main() {
    let b = Box::new(5i32);
    drop(b);
}
