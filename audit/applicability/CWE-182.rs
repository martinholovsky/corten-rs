//@ compiles: safe
// CWE-182, collapse of data into unsafe value. Removing "../" once turns
// "....//" into "../", so the filter produces the value it meant to forbid.
pub fn sanitize_path(p: &str) -> String {
    p.replace("../", "")
}
