//@ compiles: safe
// CWE-694, multiple resources with a duplicate identifier. Handlers are
// registered by name without a uniqueness check; a plugin registering "auth"
// before the real one shadows it, because lookup returns the first match.
pub type Handler = fn(&str) -> bool;
pub fn register(table: &mut Vec<(String, Handler)>, name: &str, h: Handler) {
    table.push((name.to_string(), h));
}
pub fn lookup(table: &[(String, Handler)], name: &str) -> Option<Handler> {
    table.iter().find(|(n, _)| n == name).map(|(_, h)| *h)
}
