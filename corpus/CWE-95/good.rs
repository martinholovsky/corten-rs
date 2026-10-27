// Matched benign program: a fixed set of operations, chosen by data.
fn apply(op: &str, a: u32, b: u32) -> Option<u32> {
    match op {
        "add" => a.checked_add(b),
        "mul" => a.checked_mul(b),
        _ => None,
    }
}
fn main() {
    println!("{:?}", apply("add", 1, 2));
}
