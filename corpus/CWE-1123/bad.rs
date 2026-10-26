//@ expect: -F unsafe-code
// CWE-1123: overwrites the machine code of a function at run time.
fn target() -> u32 {
    1
}
fn main() {
    let f: fn() -> u32 = target;
    let code = f as *mut u8;
    unsafe { code.write(0xc3) };
    println!("{}", target());
}
