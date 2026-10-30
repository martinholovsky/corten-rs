//@ rejected: use of moved value
// CWE-1341: releasing an owned handle twice is refused; drop moves it.
pub fn close_twice(f: std::fs::File) {
    drop(f);
    drop(f);
}
