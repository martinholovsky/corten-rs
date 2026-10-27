//@ compiles: safe
// CWE-1333, inefficient pattern-matching complexity. A backtracking wildcard
// matcher is exponential on patterns like "*a*a*a*a*b" against "aaaa...".
pub fn matches(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => matches(&p[1..], s) || (!s.is_empty() && matches(p, &s[1..])),
        (Some(a), Some(b)) if a == b => matches(&p[1..], &s[1..]),
        _ => false,
    }
}
