//@ kind: language
//@ deps: corten-std
//@ expect: E0499
// CWE-619: a statement runs on the connection while a cursor on it is still
// open. The cursor borrows the connection exclusively, so this does not build.
use corten_std::sql::SqlExecutor;

pub fn purge<D: SqlExecutor>(db: &mut D) -> Result<usize, D::Error> {
    let open = db.query(&corten_std::sql!("SELECT id FROM sessions"))?;
    db.execute(&corten_std::sql!("DELETE FROM sessions"))?;
    Ok(open.count())
}

fn main() {}
