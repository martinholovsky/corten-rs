//@ expect: E0004
// CWE-478: a multi-way branch with no default case.
fn name(v: u8) -> &'static str {
    match v {
        1 => "one",
        2 => "two",
    }
}
fn main() {
    println!("{}", name(3));
}
