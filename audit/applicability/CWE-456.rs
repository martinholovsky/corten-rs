//@ rejected: possibly-uninitialized
// CWE-456, missing initialisation of a variable. Rust's definite-assignment
// analysis (E0381) rejects reading `limit` on the path where it was never set.
pub fn limit_for(premium: bool) -> u32 {
    let limit: u32;
    if premium {
        limit = 100;
    }
    limit
}
