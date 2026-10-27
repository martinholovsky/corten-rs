fn main() {
    let src = [1u64, 2];
    let mut dst = [0u64; 2];
    dst.copy_from_slice(&src);
    println!("{dst:?}");
}
