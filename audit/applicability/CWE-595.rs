//@ compiles: safe
// CWE-595, comparing object references instead of contents. `==` on Rust
// references compares contents, but std::ptr::eq (safe) compares
// addresses, so two equal tokens held in different buffers compare unequal.
pub fn same_token(a: &String, b: &String) -> bool {
    std::ptr::eq(a, b)
}
