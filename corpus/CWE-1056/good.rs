fn sum(xs: &[u32]) -> Option<u32> {
    xs.iter().try_fold(0u32, |acc, x| acc.checked_add(*x))
}
fn main() {
    println!("{:?}", sum(&[1, 2, 3]));
}
