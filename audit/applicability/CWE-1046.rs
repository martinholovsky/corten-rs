//@ compiles: safe
// CWE-1046, building text by repeated concatenation into new strings.
// format! allocates a fresh String each iteration, copying everything so far
// (quadratic), instead of push_str into one buffer.
pub fn join(parts: &[&str]) -> String {
    let mut s = String::new();
    for p in parts {
        s = format!("{s}{p},");
    }
    s
}
