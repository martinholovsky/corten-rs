fn name(v: u8) -> &'static str {
    match v {
        1 => "one",
        2 => "two",
        _ => "other",
    }
}
fn main() {
    println!("{}", name(3));
}
