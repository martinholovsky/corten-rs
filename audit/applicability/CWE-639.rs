//@ compiles: safe
// CWE-639, authorization bypass through a user-controlled key: the record id
// from the request selects the record and its owner is never compared with
// the caller.
use std::collections::HashMap;
pub struct Invoice { pub owner: String, pub body: String }
pub fn get_invoice<'a>(db: &'a HashMap<u64, Invoice>, _caller: &str, id_param: &str) -> Option<&'a str> {
    let id: u64 = id_param.parse().ok()?;
    db.get(&id).map(|i| i.body.as_str())
}
