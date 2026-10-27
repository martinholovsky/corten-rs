//@ rejected: cannot be sent between threads safely
// CWE-567 attempted in safe Rust: shared unsynchronised state (Rc<RefCell>)
// cannot cross into another thread; Send/Sync reject it.
use std::cell::RefCell;
use std::rc::Rc;
pub fn count() {
    let hits = Rc::new(RefCell::new(0u64));
    let h2 = Rc::clone(&hits);
    let t = std::thread::spawn(move || *h2.borrow_mut() += 1);
    *hits.borrow_mut() += 1;
    let _ = t.join();
}
