//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let template = String::from("(uid={})");
    let _f = corten_std::ldap_filter!(template, "x");
}
