//@ rejected: mismatched types
// CWE-481, assigning instead of comparing. In Rust an assignment has type (),
// and `if` requires bool, so `if x = 0` is a type error in safe and unsafe
// code alike.
pub fn is_root(uid: u32) -> bool {
    let mut uid = uid;
    if uid = 0 { true } else { false }
}
