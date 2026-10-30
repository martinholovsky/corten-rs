//@ compiles: unsafe
// CWE-1098, pointer member without proper copy control: derived Clone copies
// the raw pointer shallowly, so both copies free the same buffer in Drop.
#[derive(Clone)]
pub struct Buf {
    ptr: *mut u8,
    len: usize,
}
impl Buf {
    pub fn new(n: usize) -> Self {
        let b = vec![0u8; n].into_boxed_slice();
        let len = b.len();
        Buf { ptr: Box::into_raw(b).cast(), len }
    }
}
impl Drop for Buf {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(self.ptr, self.len))) }
    }
}
