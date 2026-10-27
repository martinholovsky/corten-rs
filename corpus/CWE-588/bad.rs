//@ expect: -F unsafe-code
// CWE-588: treats a pointer to bytes as a pointer to a struct.
struct Header {
    len: u32,
}
fn main() {
    let bytes = [3u8, 0];
    let h = bytes.as_ptr().cast::<Header>();
    let len = unsafe { (*h).len };
    println!("{len}");
}
