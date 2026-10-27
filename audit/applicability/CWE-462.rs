//@ compiles: safe
// CWE-462, duplicate key in an association list: "role" appears twice and
// lookup silently returns the first.
pub fn lookup<'a>(alist: &[(&'a str, &'a str)], k: &str) -> Option<&'a str> {
    alist.iter().find(|(key, _)| *key == k).map(|(_, v)| *v)
}
pub fn claims() -> Vec<(&'static str, &'static str)> {
    vec![("role", "user"), ("role", "admin")]
}
