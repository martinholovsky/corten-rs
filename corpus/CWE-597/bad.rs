//@ expect: E0277
// CWE-597: compares strings by reference with ==. In Rust, == on strings
// compares contents, so the mistake cannot be written; the nearest form,
// comparing a String with a number, does not compile.
fn main() {
    let a = String::from("x");
    if a == 1 {
        println!("same");
    }
}
