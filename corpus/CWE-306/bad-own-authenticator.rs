//@ kind: language
//@ deps: corten-std
//@ expect: private
// CWE-306 variant: an authenticator with keys the program chose. It is built only
// from a signed manifest grant (`new` is not public).
use corten_std::authz::TokenAuthenticator;

pub fn mine(key: [u8; 32]) -> Option<TokenAuthenticator> {
    TokenAuthenticator::new(String::from("api"), &[(String::from("k1"), key)])
}

fn main() {}
