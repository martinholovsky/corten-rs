//@ rejected: E0133
// CWE-121 attempted in safe Rust: the raw write is refused; indexing the stack
// array instead is bounds-checked.
pub fn fill(n: usize) -> u8 {
    let mut stack_buf = [0u8; 8];
    let p = stack_buf.as_mut_ptr();
    for i in 0..n {
        p.add(i).write(0x41);
    }
    stack_buf[0]
}
