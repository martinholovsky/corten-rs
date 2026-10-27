//@ compiles: safe
// CWE-248, uncaught exception: a malformed value panics, and nothing catches
// the unwind, so the thread (or process, with panic=abort) dies.
pub fn port(value: &str) -> u16 {
    value.parse().unwrap()
}
