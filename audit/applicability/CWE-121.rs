//@ compiles: unsafe
// CWE-121, stack-based buffer overflow: writes `n` bytes into a stack array
// of 8 through a raw pointer.
pub fn fill(n: usize) -> u8 {
    let mut stack_buf = [0u8; 8];
    let p = stack_buf.as_mut_ptr();
    for i in 0..n {
        unsafe { p.add(i).write(0x41) };
    }
    stack_buf[0]
}
