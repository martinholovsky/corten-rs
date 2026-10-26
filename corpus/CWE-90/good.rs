//@ deps: corten-std
use corten_std::ldap::LdapSearcher;

pub fn lookup<L: LdapSearcher>(ldap: &mut L, user: &str) -> Result<Vec<String>, L::Error> {
    let base = corten_std::ldap_dn!("ou=people,dc=example,dc=org");
    ldap.search(&base, &corten_std::ldap_filter!("(&(uid={})(objectClass=person))", user))
}

fn main() {}
