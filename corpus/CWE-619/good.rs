//@ deps: corten-std
use corten_std::sql::SqlExecutor;

pub fn purge<D: SqlExecutor>(db: &mut D) -> Result<usize, D::Error> {
    let open = db.query(&corten_std::sql!("SELECT id FROM sessions"))?.count();
    db.execute(&corten_std::sql!("DELETE FROM sessions"))?;
    Ok(open)
}

fn main() {}
