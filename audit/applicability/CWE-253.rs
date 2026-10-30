//@ compiles: safe
// CWE-253, incorrect check of return value: Write::write may write fewer
// bytes than given; checking only is_ok() treats a short write as complete.
use std::io::Write;
pub fn send(out: &mut impl Write, msg: &[u8]) -> bool {
    out.write(msg).is_ok()
}
