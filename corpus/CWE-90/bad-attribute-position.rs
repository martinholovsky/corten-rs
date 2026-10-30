//@ kind: language
//@ deps: corten-std
//@ expect: ldap_filter!: a placeholder
// CWE-90 variant (encoder pre-review, 2026-10-27): the placeholder sits where
// the attribute name goes. The value is escaped for a filter value, which
// leaves `>`, `<`, `~` and `:` alone: `uid>` turns `=` into `>=`, `uid:dn:`
// makes an extensible match. Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn filter(attr: &str) -> corten_std::ldap::LdapFilter {
    corten_std::ldap_filter!("({}=admin)", attr)
}

fn main() {}
