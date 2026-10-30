//@ compiles: safe
// CWE-911, improper reference-count update. Forgetting an Rc clone is safe and
// leaves the strong count one too high, so the object is never freed.
use std::rc::Rc;
pub fn register(shared: &Rc<Vec<u8>>) {
    let extra = Rc::clone(shared);
    std::mem::forget(extra);
}
