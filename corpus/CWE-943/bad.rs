//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-943: a query built by string formatting.
use corten_std::sql::SqlExecutor;

pub fn find<D: SqlExecutor>(db: &mut D, name: &str) -> bool {
    let query = format!("SELECT id FROM users WHERE name = '{name}'");
    db.execute(&query).is_ok()
}

fn main() {}
