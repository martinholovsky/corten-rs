//@ expect: -F unsafe-code
// CWE-111 (Rust form): calling native code through FFI, as JNI does.
unsafe extern "C" {
    fn abs(input: i32) -> i32;
}
fn main() {
    let v = unsafe { abs(-3) };
    println!("{v}");
}
