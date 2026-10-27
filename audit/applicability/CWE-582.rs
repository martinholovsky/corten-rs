//@ rejected: immutable static item
// CWE-582, public final static array whose contents can still be modified.
// A Rust `static` is deeply immutable: element assignment is a compile error
// (only an explicitly mutable `static mut` or interior-mutable type differs).
pub static ADMIN_IDS: [u32; 2] = [1, 2];
pub fn attacker() {
    ADMIN_IDS[0] = 666;
}
