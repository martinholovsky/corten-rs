//@ lint: corten_rc_cycle
//@ expect: `Node` has a destructor and can form an Rc/Arc cycle
//@ count: 1
use std::cell::RefCell;
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
struct Node {
    next: RefCell<Option<Rc<Node>>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        println!("released");
    }
}
// Not reported: the back edge is Weak.
struct Parent {
    children: RefCell<Vec<Rc<Child>>>,
}
struct Child {
    parent: RefCell<Weak<Parent>>,
}
impl Drop for Parent {
    fn drop(&mut self) {
        println!("parent");
    }
}
// Not reported: no destructor (a leak, not a skipped destructor).
struct Plain {
    next: Mutex<Option<Arc<Plain>>>,
}
// Not reported: no interior mutability, so no cycle can be closed.
struct Frozen {
    next: Option<Rc<Frozen>>,
}
impl Drop for Frozen {
    fn drop(&mut self) {}
}
fn main() {
    let n = Node { next: RefCell::new(None) };
    let p = Rc::new(Parent { children: RefCell::new(Vec::new()) });
    let c = Child { parent: RefCell::new(Rc::downgrade(&p)) };
    let q = Plain { next: Mutex::new(None) };
    let f = Frozen { next: None };
    println!("{} {} {} {} {}", n.next.borrow().is_none(), p.children.borrow().len(), c.parent.borrow().upgrade().is_some(), q.next.lock().is_ok(), f.next.is_none());
}
