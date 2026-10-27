//@ expect: is not supported for non-extern functions
// CWE-1056: a function with variadic parameters.
fn sum(count: u32, ...) -> u32 {
    count
}
fn main() {
    println!("{}", sum(3));
}
