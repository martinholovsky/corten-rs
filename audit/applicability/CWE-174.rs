//@ compiles: safe
// CWE-174, double decoding. The ".." check runs after one percent-decode,
// the path is decoded again before use: "%252e%252e" passes the check and
// becomes "..".
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
pub fn resolve(raw: &str) -> Option<String> {
    let once = percent_decode(raw);
    if once.contains("..") {
        return None;
    }
    Some(percent_decode(&once))
}
