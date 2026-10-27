//@ expect: -F unsafe-code
// CWE-242: calls gets(), which cannot bound its write.
unsafe extern "C" {
    fn gets(buf: *mut u8) -> *mut u8;
}
fn main() {
    let mut buf = [0u8; 16];
    let _r = unsafe { gets(buf.as_mut_ptr()) };
}
