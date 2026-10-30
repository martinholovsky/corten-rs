//@ rejected: mismatched types
// CWE-1024 variant: the implicit spelling. rustc has no implicit numeric
// promotion, so comparing values of different integer types directly is
// rejected; only an explicit cast or a user PartialEq impl compiles.
pub fn within_quota(requested: u64, quota: u32) -> bool {
    requested <= quota
}
