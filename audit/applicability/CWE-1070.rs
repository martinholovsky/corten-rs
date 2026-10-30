//@ rejected: no method named `serialize` found
// CWE-1070: serialization in Rust is a trait (std-only stand-in for serde's
// Serialize). A serializable type with a non-serializable field does not
// compile, rather than failing at run time as in Java/.NET.
pub trait Serialize {
    fn serialize(&self, out: &mut String);
}
impl Serialize for u32 {
    fn serialize(&self, out: &mut String) {
        out.push_str(&self.to_string());
    }
}
pub struct Socket;
pub struct Session {
    id: u32,
    conn: Socket,
}
impl Serialize for Session {
    fn serialize(&self, out: &mut String) {
        self.id.serialize(out);
        self.conn.serialize(out);
    }
}
