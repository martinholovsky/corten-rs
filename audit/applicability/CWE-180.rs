//@ compiles: safe
// CWE-180, validate before canonicalize: the check runs on the raw path, then
// the path is canonicalised ("a/./../.." collapses) and used.
use std::path::{Component, Path, PathBuf};
pub fn resolve(base: &Path, user: &str) -> Option<PathBuf> {
    if user.starts_with("../") || user.starts_with('/') {
        return None;
    }
    let mut out = base.to_path_buf();
    for c in Path::new(user).components() {
        match c {
            Component::ParentDir => { out.pop(); }
            Component::Normal(p) => out.push(p),
            _ => {}
        }
    }
    Some(out)
}
