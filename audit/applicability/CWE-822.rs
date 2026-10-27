//@ compiles: unsafe
// CWE-822, untrusted pointer dereference: a pointer value received from a
// client is dereferenced.
pub fn handle(msg_ptr_from_client: usize) -> u8 {
    unsafe { *(msg_ptr_from_client as *const u8) }
}
