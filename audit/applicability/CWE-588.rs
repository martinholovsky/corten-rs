//@ rejected: dereference of raw pointer is unsafe
// CWE-588, accessing a child of a non-structure pointer. Reinterpreting a
// pointer to u32 as a pointer to a struct and reading a field needs a raw
// pointer dereference, which safe Rust rejects (E0133).
#[repr(C)]
pub struct Hdr {
    pub kind: u32,
    pub len: u32,
}
pub fn len_of(x: &u32) -> u32 {
    let p = x as *const u32 as *const Hdr;
    (*p).len
}
