//@ kind: language
//@ deps: corten-std
//@ expect: E0515
// CWE-619: a cursor handed back after its connection is gone (dangling).
use corten_std::sql::{Rows, SqlExecutor};

pub fn sessions<'a, D: SqlExecutor>(mut db: D) -> Result<Rows<'a>, D::Error> {
    db.query(&corten_std::sql!("SELECT id FROM sessions"))
}

fn main() {}
