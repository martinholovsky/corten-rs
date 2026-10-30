//@ rejected: mismatched types
// CWE-1235, autoboxing in hot paths. Rust never boxes implicitly: a value
// where a Box is expected is a type error, so every allocation is spelled
// Box::new(..) in the source.
pub fn boxed() -> Box<i32> {
    5
}
