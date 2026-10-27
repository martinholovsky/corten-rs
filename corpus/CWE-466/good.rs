fn find(xs: &[u8], i: usize) -> Option<&u8> {
    xs.get(i)
}
fn main() {
    println!("{:?}", find(&[1, 2, 3], 5));
}
