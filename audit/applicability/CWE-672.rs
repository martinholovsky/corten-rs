//@ compiles: safe
// CWE-672, use after release. A slab hands out plain indices; after remove()
// the old handle still works, and once the slot is reused it reaches another
// user's session. The borrow checker sees only integers.
pub struct Sessions {
    pub slots: Vec<Option<String>>,
}
impl Sessions {
    pub fn remove(&mut self, id: usize) {
        self.slots[id] = None;
    }
    pub fn insert(&mut self, user: String) -> usize {
        match self.slots.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.slots[i] = Some(user);
                i
            }
            None => {
                self.slots.push(Some(user));
                self.slots.len() - 1
            }
        }
    }
    pub fn user(&self, id: usize) -> Option<&String> {
        self.slots[id].as_ref()
    }
}
