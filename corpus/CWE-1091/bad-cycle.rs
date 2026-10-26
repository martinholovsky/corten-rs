//@ expect: cycle
// CWE-1091 through an Rc cycle: the destructor never runs and no lint
// sees it. Needs the no-cycles-of-linear-resources rule (not implemented).
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
