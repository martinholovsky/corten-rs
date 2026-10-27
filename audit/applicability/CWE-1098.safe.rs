//@ rejected: the trait `Copy` cannot be implemented for this type
// CWE-1098: an owning pointer cannot be shallow-copied in safe Rust; Box is
// not Copy, and its Clone copies the pointee.
#[derive(Clone, Copy)]
pub struct Buf {
    data: Box<[u8]>,
}
