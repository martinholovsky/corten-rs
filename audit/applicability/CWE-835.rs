//@ compiles: safe
// CWE-835, infinite loop: a u8 is always <= 255, so the exit condition is
// unreachable (rustc only warns about the comparison).
pub fn fill_table(t: &mut [u8; 256]) {
    let mut i: u8 = 0;
    while i <= 255 {
        t[i as usize] = i;
        i = i.wrapping_add(1);
    }
}
