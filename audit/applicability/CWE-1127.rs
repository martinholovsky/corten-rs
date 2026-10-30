//@ compiles: safe
// CWE-1127, compilation with insufficient warnings: the crate silences
// every lint (dead code, unused results, deprecated calls) at its root.
#![allow(unused, deprecated, unused_must_use)]
pub fn f(s: &str) -> &str {
    s.trim_left()
}
