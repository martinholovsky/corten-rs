//@ compiles: safe
// CWE-1075, unconditional control transfer outside a switch: Rust has no
// goto, but `break 'label` out of a labeled block is a goto-like jump.
pub fn parse(b: &[u8]) -> u32 {
    let mut v = 0;
    'done: {
        for &c in b {
            if c == b';' {
                break 'done;
            }
            v = v * 10 + u32::from(c.wrapping_sub(b'0'));
        }
        v = 0;
    }
    v
}
