//@ compiles: safe
// CWE-619, dangling database cursor. The cursor (stub) is closed in Drop,
// but std::mem::forget is safe, so the close never runs and the open cursor
// stays registered with the database session.
pub struct Cursor { id: u64 }
fn db_close_cursor(_id: u64) {}
impl Drop for Cursor {
    fn drop(&mut self) { db_close_cursor(self.id); }
}
pub fn query(id: u64) -> u64 {
    let c = Cursor { id };
    let first = c.id;
    std::mem::forget(c);
    first
}
