//@ compiles: safe
// CWE-289, authentication bypass by alternate name: the deny list compares
// names case-sensitively while the account store is case-insensitive, so
// "Mallory" passes the check and logs in as "mallory".
pub fn is_blocked(user: &str) -> bool {
    ["mallory"].contains(&user)
}
pub fn lookup(user: &str) -> String {
    user.to_ascii_lowercase()
}
pub fn login(user: &str) -> Option<String> {
    if is_blocked(user) { None } else { Some(lookup(user)) }
}
