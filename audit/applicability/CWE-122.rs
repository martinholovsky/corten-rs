//@ compiles: unsafe
// CWE-122, heap-based buffer overflow: writes past the length of a heap
// allocation through its raw pointer.
pub fn append(v: &mut Vec<u8>, data: &[u8]) {
    let end = v.len();
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), v.as_mut_ptr().add(end), data.len());
        v.set_len(end + data.len());
    }
}
