//@ compiles: safe
// CWE-90, LDAP injection. "*)(uid=*" widens the filter to every entry.
// ldap_search stands in for an LDAP client.
pub fn ldap_search(_filter: &str) -> Vec<String> {
    Vec::new()
}
pub fn lookup(user: &str) -> Vec<String> {
    ldap_search(&format!("(&(objectClass=person)(uid={user}))"))
}
