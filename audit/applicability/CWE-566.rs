//@ compiles: safe
// CWE-566, authorization bypass through a user-controlled SQL primary key:
// the query is parameterised (no injection) but selects by the caller-chosen
// id with no owner predicate. query() is a stub for the database driver.
pub fn query(_sql: &str, _params: &[&str]) -> Vec<String> { Vec::new() }
pub fn message(_session_user: &str, id_param: &str) -> Vec<String> {
    query("SELECT body FROM messages WHERE id = ?", &[id_param])
}
