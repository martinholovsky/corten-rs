//@ rejected: can't compare
// CWE-597, wrong operator in string comparison (Java's `==` meaning
// identity). Rust has no identity `==`: PartialEq on String/str compares
// contents, and mixing a reference with an owned String, the closest
// spelling of comparing "a reference against an object", is refused.
pub fn is_admin(name: &String, admin: String) -> bool {
    name == admin
}
