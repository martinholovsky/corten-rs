//@ expect: -F unsafe-code
// CWE-500: a public static field that is not constant.
pub static mut RETRIES: u32 = 3;
fn main() {
    unsafe { RETRIES = 0 };
    let v = unsafe { RETRIES };
    println!("{v}");
}
