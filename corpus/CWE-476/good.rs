fn first(xs: &[u32]) -> Option<&u32> {
    xs.first()
}
fn main() {
    match first(&[]) {
        Some(v) => println!("{v}"),
        None => println!("empty"),
    }
}
