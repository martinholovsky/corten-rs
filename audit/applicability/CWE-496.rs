//@ compiles: safe
// CWE-496, public data assigned to a private array field. With shared
// ownership (Rc<RefCell<..>>) the caller keeps a handle and can still change
// the "private" allow-list after handing it over.
use std::cell::RefCell;
use std::rc::Rc;
pub struct Firewall {
    allowed: Rc<RefCell<Vec<String>>>,
}
impl Firewall {
    pub fn new(allowed: Rc<RefCell<Vec<String>>>) -> Self {
        Firewall { allowed }
    }
    pub fn permits(&self, host: &str) -> bool {
        self.allowed.borrow().iter().any(|h| h == host)
    }
}
