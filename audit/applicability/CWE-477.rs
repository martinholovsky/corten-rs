//@ compiles: safe
// CWE-477, obsolete function: str::trim_left is deprecated (superseded by
// trim_start); rustc only warns.
pub fn strip(s: &str) -> &str {
    #[allow(deprecated)]
    s.trim_left()
}
