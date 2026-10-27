//@ compiles: safe
// CWE-771, missing reference to an allocated resource. Box::leak returns the
// only reference, which is discarded; the buffer can never be freed.
pub fn scratch(n: usize) {
    let _ = Box::leak(vec![0u8; n].into_boxed_slice());
}
