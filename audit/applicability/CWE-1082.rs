//@ compiles: unsafe
// CWE-1082, instance destroys itself ("delete this"): frees the Box that owns
// `self` while the caller still holds the reference.
pub struct Node {
    pub data: Vec<u8>,
}
impl Node {
    pub fn destroy(&self) {
        unsafe { drop(Box::from_raw(self as *const Node as *mut Node)) }
    }
}
