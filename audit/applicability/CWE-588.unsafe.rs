//@ compiles: unsafe
// CWE-588 in unsafe Rust: the u32 is treated as a Hdr and `len` is read past
// the end of the 4-byte object.
#[repr(C)]
pub struct Hdr {
    pub kind: u32,
    pub len: u32,
}
pub fn len_of(x: &u32) -> u32 {
    let p = x as *const u32 as *const Hdr;
    unsafe { (*p).len }
}
