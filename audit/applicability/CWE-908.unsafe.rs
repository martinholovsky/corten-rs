//@ compiles: unsafe
// CWE-908 in unsafe Rust: set_len exposes uninitialised heap memory, which is
// then sent (undefined behaviour, and an information leak in practice).
pub fn send(out: &mut Vec<u8>) {
    let mut buf: Vec<u8> = Vec::with_capacity(16);
    unsafe { buf.set_len(16) };
    out.extend_from_slice(&buf);
}
