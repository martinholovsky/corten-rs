fn main() {
    let v = vec![1u8, 2, 3].into_boxed_slice();
    drop(v);
}
