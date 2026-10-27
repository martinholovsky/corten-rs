//@ expect: -F unsafe-code
// CWE-1098: a struct holding an owning raw pointer with a bitwise copy.
#[derive(Clone, Copy)]
struct Buffer {
    data: *mut u8,
}
impl Buffer {
    fn free(self) {
        unsafe { drop(Box::from_raw(self.data)) };
    }
}
fn main() {
    let a = Buffer { data: Box::into_raw(Box::new(1u8)) };
    let b = a;
    a.free();
    b.free();
}
