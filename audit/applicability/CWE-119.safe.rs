//@ rejected: E0133
// CWE-119 attempted in safe Rust. The unchecked access needs a raw pointer
// dereference, which safe code may not perform; the safe spelling `buf[i] = v`
// is bounds-checked and panics instead (CWE-129/248, not an access outside).
pub fn poke(i: usize, v: u8) {
    let mut buf = [0u8; 4];
    let p = buf.as_mut_ptr();
    *p.add(i) = v;
}
