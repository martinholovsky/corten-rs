//@ expect: -F unsafe-code
// CWE-475: passes input that violates an API's precondition.
fn main() {
    let bytes = vec![0xffu8, 0x41];
    let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
    println!("{s}");
}
