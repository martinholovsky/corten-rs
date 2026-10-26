//@ expect: -F clippy::as-conversions
// CWE-704: a narrowing cast that silently truncates.
fn main() {
    let big: u32 = 300;
    let small = big as u8;
    println!("{small}");
}
