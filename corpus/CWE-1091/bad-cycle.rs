//@ expect: cycle
// CWE-1091 through an Rc cycle: the destructor never runs. Caught by the
// Rc/Arc-cycle lint (corten-driver, Phase 3b), which decides on types.
use std::cell::RefCell;
use std::rc::Rc;
struct Node {
    next: RefCell<Option<Rc<Node>>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        println!("released");
    }
}
fn main() {
    let a = Rc::new(Node { next: RefCell::new(None) });
    let b = Rc::new(Node { next: RefCell::new(Some(Rc::clone(&a))) });
    *a.next.borrow_mut() = Some(Rc::clone(&b));
}
