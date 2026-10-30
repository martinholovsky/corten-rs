//@ compiles: safe
// CWE-187, partial string comparison. The password check compares only as
// many bytes as the user supplied, so an empty or one-character guess that
// is a prefix of the secret is accepted. Slicing is bounds-checked; the
// logic is still wrong.
pub fn check_password(stored: &str, supplied: &str) -> bool {
    stored.starts_with(supplied)
}
