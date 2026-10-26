//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let f = corten_std::ldap::LdapFilter(String::from("(uid=*)"));
    println!("{f:?}");
}
