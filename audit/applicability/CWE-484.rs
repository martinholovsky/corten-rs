//@ rejected: `break` outside of a loop
// CWE-484: Rust's `match` has no fall-through and no switch-level `break`;
// arms are exclusive. The C spelling (`break` ending a case) is refused.
pub fn flags(code: u8) -> u32 {
    let mut f = 0;
    match code {
        1 => {
            f |= 1;
        }
        2 => {
            f |= 2;
            break;
        }
        _ => {}
    }
    f
}
