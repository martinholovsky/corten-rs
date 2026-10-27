//@ compiles: safe
// CWE-628, incorrectly specified arguments: clamp(hi, lo) is always wrong
// (it panics whenever hi > lo); the types cannot tell the bounds apart.
pub fn limit(v: i32, lo: i32, hi: i32) -> i32 {
    v.clamp(hi, lo)
}
