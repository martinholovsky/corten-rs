//@ compiles: safe
// CWE-647, non-canonical URL paths for authorization: the protected prefix is
// matched on the raw path, so "//admin" or "/./admin" skip the check while the
// file server resolves them to /admin.
pub fn allowed(raw_path: &str, is_admin: bool) -> bool {
    is_admin || !raw_path.starts_with("/admin")
}
