//@ compiles: safe
// CWE-89, SQL injection. The name is formatted into the SQL text, so
// "' OR '1'='1" changes the query. db_query stands in for a database driver.
pub fn db_query(_sql: &str) -> Vec<String> {
    Vec::new()
}
pub fn find_user(name: &str) -> Vec<String> {
    db_query(&format!("SELECT * FROM users WHERE name = '{name}'"))
}
