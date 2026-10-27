//@ compiles: safe
// CWE-551, authorization before canonicalization: the admin check runs on the
// raw path, then the path is percent-decoded, so "/%61dmin" reaches /admin.
fn decode(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&p[i + 1..i + 3], 16) { out.push(v); i += 3; continue; }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
pub fn route(raw_path: &str, is_admin: bool) -> Option<String> {
    if raw_path.starts_with("/admin") && !is_admin { return None; }
    Some(decode(raw_path))
}
