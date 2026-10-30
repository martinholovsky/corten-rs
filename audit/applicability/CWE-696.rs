//@ compiles: safe
// CWE-696, incorrect behavior order: the record is deleted before ownership is
// checked.
pub fn delete(store: &mut Vec<(u32, u32)>, id: u32, user: u32) -> bool {
    let Some(pos) = store.iter().position(|r| r.0 == id) else { return false };
    let (_, owner) = store.remove(pos);
    owner == user
}
