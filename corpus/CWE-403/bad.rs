//@ expect: -F unsafe-code
// CWE-403: dup() returns a descriptor without close-on-exec, so any child
// started later inherits it.
unsafe extern "C" {
    fn dup(fd: i32) -> i32;
}
fn main() {
    let fd = unsafe { dup(1) };
    println!("{fd}");
}
