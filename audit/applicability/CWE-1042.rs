//@ rejected: associated `static` items are not allowed
// CWE-1042, static member data in a non-singleton class. Rust has no static
// members: an associated static in an impl is refused; module statics are
// not members of any type.
pub struct Connection;
impl Connection {
    static OPEN_COUNT: u32 = 0;
}
