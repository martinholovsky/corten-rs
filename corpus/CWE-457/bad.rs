//@ expect: E0381
// CWE-457: reads a variable that is initialised on one path only.
fn main() {
    let flag = true;
    let x: u32;
    if flag {
        x = 1;
    }
    println!("{x}");
}
