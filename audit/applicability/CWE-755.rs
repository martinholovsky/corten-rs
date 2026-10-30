//@ compiles: safe
// CWE-755, improper handling of exceptional conditions: an error from the
// signature check is handled by treating the input as valid (fail open).
pub fn verified(check: impl Fn() -> Result<bool, std::io::Error>) -> bool {
    match check() {
        Ok(v) => v,
        Err(_) => true,
    }
}
