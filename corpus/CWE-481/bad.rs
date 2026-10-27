//@ expect: E0308
// CWE-481: assigns where it meant to compare.
fn main() {
    let mut x = 4;
    if x = 5 {
        println!("five");
    }
    println!("{x}");
}
