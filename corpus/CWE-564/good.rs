//@ deps: corten-std
use corten_std::sql::SqlExecutor;

pub fn find<D: SqlExecutor>(db: &mut D, name: &str) -> Result<u64, D::Error> {
    db.execute(&corten_std::sql!("SELECT id FROM users WHERE name = {}", name))
}

fn main() {}
