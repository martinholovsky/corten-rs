//@ expect: -F unsafe-code
// CWE-843: reads an integer as a float through a reinterpreted pointer.
fn main() {
    let x: u64 = 1;
    let r: &f64 = unsafe { &*(&raw const x).cast::<f64>() };
    println!("{r}");
}
