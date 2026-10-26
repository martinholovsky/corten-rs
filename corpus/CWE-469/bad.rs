//@ expect: -F unsafe-code
// CWE-469: computes a length by subtracting pointers.
fn main() {
    let xs = [1u32, 2, 3, 4];
    let start = xs.as_ptr();
    let end = unsafe { start.add(2) };
    let n = unsafe { end.offset_from(start) };
    println!("{n}");
}
