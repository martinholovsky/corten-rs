//@ compiles: safe
// CWE-401, missing release of memory. Leaking is safe Rust: std documents
// that "Rust's safety guarantees do not include a guarantee that destructors
// will always run" (std::mem::forget). An Rc cycle never frees its nodes.
use std::cell::RefCell;
use std::rc::Rc;
pub struct Node {
    pub next: RefCell<Option<Rc<Node>>>,
}
pub fn leak_a_cycle() {
    let a = Rc::new(Node { next: RefCell::new(None) });
    let b = Rc::new(Node { next: RefCell::new(Some(Rc::clone(&a))) });
    *a.next.borrow_mut() = Some(b);
}
