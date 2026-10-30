//@ compiles: safe
// CWE-178, improper handling of case sensitivity. The deny check compares
// exactly, but the router/file system behind it is case-insensitive, so
// "/ADMIN" is not blocked.
pub fn is_blocked(path: &str) -> bool {
    path == "/admin"
}
