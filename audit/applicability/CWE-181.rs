//@ compiles: safe
// CWE-181, validate before filter: the tag check runs before NUL bytes are
// stripped, so "<scr\0ipt>" passes and becomes "<script>".
pub fn sanitize(input: &str) -> Option<String> {
    if input.to_lowercase().contains("<script") {
        return None;
    }
    Some(input.replace('\0', ""))
}
