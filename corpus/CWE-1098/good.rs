#[derive(Clone)]
struct Buffer {
    data: Box<[u8]>,
}
fn main() {
    let a = Buffer { data: vec![1u8, 2].into_boxed_slice() };
    let b = a.clone();
    drop(a);
    println!("{:?}", b.data);
}
