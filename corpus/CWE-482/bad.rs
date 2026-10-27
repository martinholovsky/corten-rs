//@ expect: -F unused-must-use
// CWE-482: a comparison written where an assignment was meant.
fn main() {
    let x = 1;
    x == 2;
    println!("{x}");
}
