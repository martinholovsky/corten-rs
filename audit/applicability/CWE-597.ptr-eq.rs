//@ compiles: safe
// CWE-597, wrong operator in string comparison. Rust's `==` on strings
// compares contents, so Java's identity mistake does not happen with `==`.
// The same mistake is still writable in safe Rust: std::ptr::eq compares
// addresses, so two equal strings in different buffers compare unequal.
pub fn same_role(granted: &str, requested: &str) -> bool {
    std::ptr::eq(granted, requested)
}
