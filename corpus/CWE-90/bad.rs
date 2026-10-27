//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-90: an LDAP filter built by string formatting.
use corten_std::ldap::LdapSearcher;

pub fn lookup<L: LdapSearcher>(ldap: &mut L, user: &str) -> bool {
    let base = corten_std::ldap_dn!("ou=people,dc=example,dc=org");
    let filter = format!("(&(uid={user})(objectClass=person))");
    ldap.search(&base, &filter).is_ok()
}

fn main() {}
