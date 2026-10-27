//@ compiles: safe
// CWE-183, permissive list of allowed inputs. The allowlist for redirect
// hosts accepts any host ending in "example.com", which also admits
// "evil-example.com". No type system judges whether a list is too wide.
pub fn redirect_allowed(host: &str) -> bool {
    const ALLOWED_SUFFIXES: [&str; 1] = ["example.com"];
    ALLOWED_SUFFIXES.iter().any(|s| host.ends_with(s))
}
