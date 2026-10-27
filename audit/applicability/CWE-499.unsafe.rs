//@ compiles: unsafe
// CWE-499, serializable class not denying serialization. With unsafe, another
// module dumps the object's raw bytes, private password field included.
mod creds {
    pub struct Creds {
        password: [u8; 16],
    }
    impl Creds {
        pub fn new() -> Self { Creds { password: [b'x'; 16] } }
    }
}
pub fn serialize(c: &creds::Creds) -> Vec<u8> {
    let p = c as *const creds::Creds as *const u8;
    unsafe { std::slice::from_raw_parts(p, std::mem::size_of::<creds::Creds>()) }.to_vec()
}
