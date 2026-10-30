//@ rejected: cannot be shared between threads safely
// CWE-1058 attempted in safe Rust: a mutable static must be Sync; a static
// with plain interior mutability is refused, and `static mut` needs unsafe.
use std::cell::RefCell;
static LAST_USER: RefCell<Option<String>> = RefCell::new(None);
pub fn handle(user: &str) {
    *LAST_USER.borrow_mut() = Some(user.to_owned());
}
