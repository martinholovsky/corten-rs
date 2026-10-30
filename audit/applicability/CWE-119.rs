//@ compiles: unsafe
// CWE-119, operation outside buffer bounds. A raw pointer write past the end
// of a 4-byte array: no bounds check exists on raw pointers.
pub fn poke(i: usize, v: u8) {
    let mut buf = [0u8; 4];
    let p = buf.as_mut_ptr();
    unsafe { *p.add(i) = v };
}
