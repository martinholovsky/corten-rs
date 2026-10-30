//@ compiles: safe
// CWE-129, improper validation of array index: the index from the request is
// used unchecked. Bounds checking turns the access into a panic (DoS), but the
// missing validation is the weakness and it compiles.
pub fn role_name(roles: &[&'static str], idx_from_request: usize) -> &'static str {
    roles[idx_from_request]
}
