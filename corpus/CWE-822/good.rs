fn read_at(xs: &[u32], i: usize) -> Option<u32> {
    xs.get(i).copied()
}
fn main() {
    println!("{:?}", read_at(&[1, 2], 9));
}
